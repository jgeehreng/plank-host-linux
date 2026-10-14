/**
 * @file src/platform/linux/cuda.cpp
 * @brief Definitions for CUDA encoding.
 */
// standard includes
#include <bitset>
#include <charconv>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <filesystem>
#include <mutex>
#include <numeric>
#include <thread>

// lib includes
#include <ffnvcodec/dynlink_loader.h>
#include <NvFBC.h>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/hwcontext_cuda.h>
#include <libavutil/imgutils.h>
}

// local includes
#include "cuda.h"
#include "graphics.h"
#include "src/config.h"
#include "src/logging.h"
#include "src/nvenc/nvenc_cuda_factory.h"
#include "src/utility.h"
#include "src/video.h"
#include "wayland.h"

/**
 * @def SUNSHINE_STRINGVIEW_HELPER(x)
 * @brief Macro for SUNSHINE STRINGVIEW HELPER.
 */
#define SUNSHINE_STRINGVIEW_HELPER(x) x##sv
/**
 * @def SUNSHINE_STRINGVIEW(x)
 * @brief Macro for SUNSHINE STRINGVIEW.
 */
#define SUNSHINE_STRINGVIEW(x) SUNSHINE_STRINGVIEW_HELPER(x)

/**
 * @def CU_CHECK(x, y)
 * @brief Macro for CU CHECK.
 */
#define CU_CHECK(x, y) \
  if (check((x), SUNSHINE_STRINGVIEW(y ": "))) \
  return -1

/**
 * @def CU_CHECK_IGNORE(x, y)
 * @brief Macro for CU CHECK IGNORE.
 */
#define CU_CHECK_IGNORE(x, y) \
  check((x), SUNSHINE_STRINGVIEW(y ": "))

namespace fs = std::filesystem;

using namespace std::literals;

namespace cuda {
  constexpr auto cudaDevAttrMaxThreadsPerBlock = (CUdevice_attribute) 1;  ///< CUDA dev attr max threads per block.
  constexpr auto cudaDevAttrMaxThreadsPerMultiProcessor = (CUdevice_attribute) 39;  ///< CUDA dev attr max threads per multi processor.

  namespace {
    /**
     * @brief Select a nearest-rank percentile from sorted timing samples.
     *
     * @param sorted Timing samples in ascending order.
     * @param percentile Fractional percentile in the range zero to one.
     * @return The selected timing sample.
     */
    double timing_percentile(const std::vector<double> &sorted, double percentile) {
      const auto rank = static_cast<std::size_t>(std::ceil(percentile * sorted.size()));
      return sorted[std::clamp<std::size_t>(rank, 1, sorted.size()) - 1];
    }

    /**
     * @brief Log aggregate CUDA conversion timing for qualification runs.
     *
     * @param name Stable boundary name for log parsing.
     * @param samples Durations in microseconds.
     */
    void log_cuda_timing(std::string_view name, const std::vector<double> &samples) {
      if (samples.size() < 60) {
        return;
      }
      auto sorted = samples;
      std::ranges::sort(sorted);
      const auto total = std::accumulate(sorted.begin(), sorted.end(), 0.0);
      BOOST_LOG(info)
        << "PLANK timing " << name
        << ": samples=" << sorted.size()
        << " mean_ms=" << total / sorted.size() / 1000.0
        << " p50_ms=" << timing_percentile(sorted, 0.50) / 1000.0
        << " p95_ms=" << timing_percentile(sorted, 0.95) / 1000.0
        << " p99_ms=" << timing_percentile(sorted, 0.99) / 1000.0
        << " max_ms=" << sorted.back() / 1000.0;
    }
  }  // namespace

  /**
   * @brief Convert a CUDA result code into Sunshine's capture status.
   *
   * @param sv String view containing the text to inspect.
   * @param name Human-readable name to assign.
   * @param description Human-readable description used in log output.
   */
  void pass_error(const std::string_view &sv, const char *name, const char *description) {
    BOOST_LOG(error) << sv << name << ':' << description;
  }

  /**
   * @brief Release a Core Foundation object when the wrapper is destroyed.
   *
   * @param cf Core Foundation object passed to the scoped releaser.
   */
  void cff(CudaFunctions *cf) {
    cuda_free_functions(&cf);
  }

  /**
   * @brief Handle to a CUDA dynamic-library function table.
   */
  using cdf_t = util::safe_ptr<CudaFunctions, cff>;

  static cdf_t cdf;

  inline static int check(CUresult result, const std::string_view &sv) {
    if (result != CUDA_SUCCESS) {
      const char *name;
      const char *description;

      cdf->cuGetErrorName(result, &name);
      cdf->cuGetErrorString(result, &description);

      BOOST_LOG(error) << sv << name << ':' << description;
      return -1;
    }

    return 0;
  }

  /**
   * @brief Release stream resources.
   *
   * @param stream CUDA stream or PipeWire stream involved in the operation.
   */
  void freeStream(CUstream stream) {
    CU_CHECK_IGNORE(cdf->cuStreamDestroy(stream), "Couldn't destroy cuda stream");
  }

  /**
   * @brief Unregister a CUDA graphics resource if it is still registered.
   *
   * @param resource CUDA graphics resource being mapped or unmapped.
   */
  void unregisterResource(CUgraphicsResource resource) {
    CU_CHECK_IGNORE(cdf->cuGraphicsUnregisterResource(resource), "Couldn't unregister resource");
  }

  /**
   * @brief CUDA graphics resource pointer released with `cuGraphicsUnregisterResource`.
   */
  using registered_resource_t = util::safe_ptr<CUgraphicsResource_st, unregisterResource>;

  /**
   * @brief CUDA image wrapper that owns mapped graphics resources for one frame.
   */
  class img_t: public platf::img_t {
  public:
    tex_t tex;  ///< CUDA texture object used as the conversion source.
  };

  /**
   * @brief Map CUDA graphics resources for use as an image.
   *
   * @return 0 on success; nonzero or negative platform status on failure.
   */
  int init() {
    auto status = cuda_load_functions(&cdf, nullptr);
    if (status) {
      BOOST_LOG(error) << "Couldn't load cuda: "sv << status;

      return -1;
    }

    CU_CHECK(cdf->cuInit(0), "Couldn't initialize cuda");

    return 0;
  }

  /**
   * @brief CUDA encode device that imports captured frames into CUDA memory.
   */
  class cuda_t: public platf::avcodec_encode_device_t {
  public:
    /**
     * @brief Initialize the CUDA device context used for frame conversion.
     *
     * @param in_width In width.
     * @param in_height In height.
     * @return 0 on success; nonzero or negative platform status on failure.
     */
    int init(int in_width, int in_height) {
      if (!cdf) {
        BOOST_LOG(warning) << "cuda not initialized"sv;
        return -1;
      }

      data = (void *) 0x1;

      width = in_width;
      height = in_height;

      return 0;
    }

    /**
     * @brief Attach frame resources used by the next conversion or encode operation.
     *
     * @param frame Video or graphics frame being processed.
     * @param hw_frames_ctx FFmpeg hardware frames context associated with the frame.
     * @return Status from updating frame.
     */
    int set_frame(AVFrame *frame, AVBufferRef *hw_frames_ctx) override {
      this->hwframe.reset(frame);
      this->frame = frame;

      auto hwframe_ctx = (AVHWFramesContext *) hw_frames_ctx->data;

      if (hwframe_ctx->sw_format != AV_PIX_FMT_NV12 && hwframe_ctx->sw_format != AV_PIX_FMT_YUV444P && hwframe_ctx->sw_format != AV_PIX_FMT_YUV444P16LE) {
        BOOST_LOG(error) << "cuda::cuda_t supports only AV_PIX_FMT_NV12, AV_PIX_FMT_YUV444P, and AV_PIX_FMT_YUV444P16LE"sv;
        return -1;
      }

      if (!frame->buf[0]) {
        if (av_hwframe_get_buffer(hw_frames_ctx, frame, 0)) {
          BOOST_LOG(error) << "Couldn't get hwframe for NVENC"sv;
          return -1;
        }
      }

      is_yuv444 = (hwframe_ctx->sw_format == AV_PIX_FMT_YUV444P || hwframe_ctx->sw_format == AV_PIX_FMT_YUV444P16LE);
      is_10bit = hwframe_ctx->sw_format == AV_PIX_FMT_YUV444P16LE;

      auto cuda_ctx = (AVCUDADeviceContext *) hwframe_ctx->device_ctx->hwctx;

      stream = make_stream();
      if (!stream) {
        return -1;
      }

      cuda_ctx->stream = stream.get();

      auto sws_opt = sws_t::make(width, height, frame->width, frame->height, width * 4);
      if (!sws_opt) {
        return -1;
      }

      sws = std::move(*sws_opt);

      linear_interpolation = width != frame->width || height != frame->height;

      return 0;
    }

    /**
     * @brief Apply the configured colorspace metadata to the active frame.
     */
    void apply_colorspace() override {
      sws.apply_colorspace(colorspace);

      auto tex = tex_t::make(height, width * 4);
      if (!tex) {
        return;
      }

      // The default green color is ugly.
      // Update the background color
      platf::img_t img;
      img.width = width;
      img.height = height;
      img.pixel_pitch = 4;
      img.row_pitch = img.width * img.pixel_pitch;

      std::vector<std::uint8_t> image_data;
      image_data.resize(img.row_pitch * img.height);

      img.data = image_data.data();

      if (sws.load_ram(img, tex->array)) {
        return;
      }

      if (is_yuv444) {
        if (is_10bit) {
          sws.convert_yuv444_10bit(frame->data[0], frame->data[1], frame->data[2], frame->linesize[0], tex->texture.linear, stream.get(), {frame->width, frame->height, 0, 0});
        } else {
          sws.convert_yuv444(frame->data[0], frame->data[1], frame->data[2], frame->linesize[0], tex->texture.linear, stream.get(), {frame->width, frame->height, 0, 0});
        }
      } else {
        sws.convert_nv12(frame->data[0], frame->data[1], frame->linesize[0], frame->linesize[1], tex->texture.linear, stream.get(), {frame->width, frame->height, 0, 0});
      }
    }

    /**
     * @brief Select the CUDA texture object for the configured filtering mode.
     *
     * @param tex Texture resource used by the converter.
     * @return CUDA texture object using linear or point sampling.
     */
    cudaTextureObject_t tex_obj(const tex_t &tex) const {
      return linear_interpolation ? tex.texture.linear : tex.texture.point;
    }

    stream_t stream;  ///< CUDA stream used for asynchronous conversion work.
    frame_t hwframe;  ///< FFmpeg hardware frame backed by CUDA resources.

    int height;  ///< Frame or display height in pixels.
    int width;  ///< Frame or display width in pixels.

    // When height and width don't change, it's not necessary to use linear interpolation
    bool linear_interpolation;  ///< Whether the CUDA converter uses linear interpolation.

    bool is_yuv444;  ///< Whether the CUDA converter outputs YUV 4:4:4.
    bool is_10bit;  ///< Whether the CUDA converter outputs MSB-aligned 10-bit samples.

    sws_t sws;  ///< Software scaler used for CUDA frame conversion fallback paths.
  };

  /**
   * @brief CUDA encode device path that converts frames through system memory.
   */
  class cuda_ram_t: public cuda_t {
  public:
    /**
     * @brief Convert a captured frame through CUDA into system-memory encoder input.
     *
     * @param img Image or frame object to read from or populate.
     * @return Conversion status.
     */
    int convert(platf::img_t &img) override {
      if (is_yuv444) {
        return sws.load_ram(img, tex.array) ||
               (is_10bit ? sws.convert_yuv444_10bit(frame->data[0], frame->data[1], frame->data[2], frame->linesize[0], tex_obj(tex), stream.get()) :
                           sws.convert_yuv444(frame->data[0], frame->data[1], frame->data[2], frame->linesize[0], tex_obj(tex), stream.get()));
      }
      return sws.load_ram(img, tex.array) || sws.convert_nv12(frame->data[0], frame->data[1], frame->linesize[0], frame->linesize[1], tex_obj(tex), stream.get());
    }

    /**
     * @brief Attach frame resources used by the next conversion or encode operation.
     *
     * @param frame Video or graphics frame being processed.
     * @param hw_frames_ctx FFmpeg hardware frames context associated with the frame.
     * @return Status from updating frame.
     */
    int set_frame(AVFrame *frame, AVBufferRef *hw_frames_ctx) override {
      if (cuda_t::set_frame(frame, hw_frames_ctx)) {
        return -1;
      }

      auto tex_opt = tex_t::make(height, width * 4);
      if (!tex_opt) {
        return -1;
      }

      tex = std::move(*tex_opt);

      return 0;
    }

    tex_t tex;  ///< CUDA texture object used as the conversion source.
  };

  /**
   * @brief CUDA encode device path that keeps converted frames in GPU memory.
   */
  class cuda_vram_t: public cuda_t {
  public:
    /**
     * @brief Convert a captured frame through CUDA into GPU encoder input.
     *
     * @param img Image or frame object to read from or populate.
     * @return Conversion status.
     */
    int convert(platf::img_t &img) override {
      if (is_yuv444) {
        return is_10bit ? sws.convert_yuv444_10bit(frame->data[0], frame->data[1], frame->data[2], frame->linesize[0], tex_obj(((img_t *) &img)->tex), stream.get()) :
                          sws.convert_yuv444(frame->data[0], frame->data[1], frame->data[2], frame->linesize[0], tex_obj(((img_t *) &img)->tex), stream.get());
      }
      return sws.convert_nv12(frame->data[0], frame->data[1], frame->linesize[0], frame->linesize[1], tex_obj(((img_t *) &img)->tex), stream.get());
    }
  };

  /**
   * @brief NvFBC CUDA readback device for latency-bounded x264 encoding.
   *
   * The qualified 8-bit and 10-bit x264 paths first create compact planar
   * identity GBR on CUDA and read those planes into pinned memory. The 8-bit
   * frame uses that readback directly; the 10-bit frame expands it to full-range
   * 10-bit samples on CPU. This avoids transferring the 49.8 MB 16-bit carrier
   * produced by direct CUDA 10-bit conversion at 4K.
   */
  class cuda_software_t final: public platf::avcodec_encode_device_t {
  public:
    /**
     * @brief Release CUDA resources and stop depth-expansion workers.
     */
    ~cuda_software_t() override {
      log_cuda_timing("cuda_dispatch", dispatch_us);
      log_cuda_timing("gpu_readback_sync", readback_sync_us);
      log_cuda_timing("cpu_depth_expansion", depth_expansion_us);
      log_cuda_timing("cuda_software_convert_total", total_conversion_us);

      for (auto &worker : workers) {
        worker.request_stop();
      }
      work_ready.notify_all();
      workers.clear();

      if (device_compact && cdf) {
        CU_CHECK_IGNORE(cdf->cuMemFree(device_compact), "Couldn't free compact identity planes");
      }
      if (host_readback && host_free) {
        CU_CHECK_IGNORE(host_free(host_readback), "Couldn't free pinned software-encoder readback");
      }
      if (cuda_driver) {
        dlclose(cuda_driver);
      }
    }

    /**
     * @brief Initialize capture dimensions and CUDA stream state.
     *
     * @param in_width Captured frame width.
     * @param in_height Captured frame height.
     * @param requested_format Software format selected during encoder negotiation.
     * @return 0 on success; -1 on invalid state.
     */
    int init(int in_width, int in_height, platf::pix_fmt_e requested_format) {
      if (!cdf || (requested_format != platf::pix_fmt_e::yuv444p &&
                   requested_format != platf::pix_fmt_e::yuv444p16 &&
                   requested_format != platf::pix_fmt_e::yuv422p &&
                   requested_format != platf::pix_fmt_e::yuv422p10)) {
        return -1;
      }

      data = reinterpret_cast<void *>(0x1);
      width = in_width;
      height = in_height;
      capture_format = requested_format;
      stream = make_stream();
      cuda_driver = dlopen("libcuda.so.1", RTLD_LAZY | RTLD_LOCAL);
      if (cuda_driver) {
        host_alloc = reinterpret_cast<host_alloc_fn_t>(dlsym(cuda_driver, "cuMemHostAlloc"));
        host_free = reinterpret_cast<host_free_fn_t>(dlsym(cuda_driver, "cuMemFreeHost"));
      }
      if (!stream || !host_alloc || !host_free) {
        BOOST_LOG(error) << "CUDA driver does not expose pinned-host allocation functions"sv;
        return -1;
      }
      return 0;
    }

    /**
     * @brief Attach the CPU frame that will be submitted to x264.
     *
     * @param new_frame FFmpeg software frame.
     * @param hw_frames_ctx Unused hardware-frame context; must be null.
     * @return 0 on success; -1 when the negotiated format is unsupported.
     */
    int set_frame(AVFrame *new_frame, AVBufferRef *hw_frames_ctx) override {
      host_frame.reset(new_frame);
      frame = new_frame;
      if (hw_frames_ctx || !frame) {
        return -1;
      }

      const bool identity_8bit = frame->format == AV_PIX_FMT_YUV444P;
      const bool identity_10bit = frame->format == AV_PIX_FMT_YUV444P10LE;
      const bool yuv422_8bit = frame->format == AV_PIX_FMT_YUV422P;
      const bool yuv422_10bit = frame->format == AV_PIX_FMT_YUV422P10LE;
      if ((!identity_8bit && !identity_10bit && !yuv422_8bit && !yuv422_10bit) ||
          (identity_8bit && capture_format != platf::pix_fmt_e::yuv444p) ||
          (identity_10bit && capture_format != platf::pix_fmt_e::yuv444p16) ||
          (yuv422_8bit && capture_format != platf::pix_fmt_e::yuv422p) ||
          (yuv422_10bit && capture_format != platf::pix_fmt_e::yuv422p10)) {
        BOOST_LOG(error) << "CUDA software encode received an unsupported frame/capture format pair"sv;
        return -1;
      }

      output_width = frame->width;
      output_height = frame->height;
      const auto scalar = std::fminf(
        output_width / static_cast<float>(width),
        output_height / static_cast<float>(height)
      );
      content_width = std::max(1, static_cast<int>(width * scalar));
      content_height = std::max(1, static_cast<int>(height * scalar));
      content_offset_x = (output_width - content_width) / 2;
      content_offset_y = (output_height - content_height) / 2;
      BOOST_LOG(info)
        << "PLANK software capture geometry: source=" << width << 'x' << height
        << " content=" << content_width << 'x' << content_height
        << '+' << content_offset_x << '+' << content_offset_y
        << " encode=" << output_width << 'x' << output_height;
      const auto plane_size = static_cast<std::size_t>(output_width) * output_height;
      host_readback_size = yuv422_8bit ? plane_size * 2U :
                           yuv422_10bit ? plane_size * 4U :
                           plane_size * 3U;
      CU_CHECK(host_alloc(&host_readback, host_readback_size, 1U), "Couldn't allocate pinned software-encoder readback");

      if (yuv422_8bit || yuv422_10bit) {
        const std::size_t bytes_per_sample = yuv422_10bit ? 2U : 1U;
        const auto luma_size = plane_size * bytes_per_sample;
        const auto chroma_size = (plane_size / 2U) * bytes_per_sample;
        auto *base = static_cast<std::uint8_t *>(host_readback);
        std::memset(base, 0, luma_size);
        if (yuv422_10bit) {
          auto *u = reinterpret_cast<std::uint16_t *>(base + luma_size);
          auto *v = reinterpret_cast<std::uint16_t *>(base + luma_size + chroma_size);
          std::fill_n(u, plane_size / 2U, static_cast<std::uint16_t>(512));
          std::fill_n(v, plane_size / 2U, static_cast<std::uint16_t>(512));
        } else {
          std::memset(base + luma_size, 128, chroma_size * 2U);
        }

        frame->data[0] = base;
        frame->data[1] = base + luma_size;
        frame->data[2] = base + luma_size + chroma_size;
        frame->linesize[0] = output_width * bytes_per_sample;
        frame->linesize[1] = frame->linesize[2] = (output_width / 2) * bytes_per_sample;

        CU_CHECK(cdf->cuMemAlloc(&device_compact, host_readback_size), "Couldn't allocate CUDA YUV422 planes");
        CU_CHECK(cdf->cuMemcpyHtoDAsync(device_compact, host_readback, host_readback_size, stream.get()),
                 "Couldn't initialize CUDA YUV422 background");
        auto converter = sws_t::make(width, height, output_width, output_height, width * 4);
        if (!converter) {
          return -1;
        }
        sws = std::move(*converter);
        mode = yuv422_10bit ? mode_e::yuv422_10bit : mode_e::yuv422_8bit;
        return 0;
      }

      if (identity_8bit) {
        auto *base = static_cast<std::uint8_t *>(host_readback);
        frame->data[0] = base;
        frame->data[1] = base + plane_size;
        frame->data[2] = base + plane_size * 2U;
        frame->linesize[0] = frame->linesize[1] = frame->linesize[2] = output_width;
      } else {
        if (av_frame_get_buffer(frame, 64) < 0) {
          BOOST_LOG(error) << "Couldn't allocate x264 10-bit software frame"sv;
          return -1;
        }
      }
      CU_CHECK(cdf->cuMemAlloc(&device_compact, host_readback_size), "Couldn't allocate compact CUDA identity planes");
      CU_CHECK(cdf->cuMemsetD8Async(device_compact, 0, host_readback_size, stream.get()),
               "Couldn't initialize identity span background");

      auto converter = sws_t::make(width, height, output_width, output_height, width * 4);
      if (!converter) {
        return -1;
      }
      sws = std::move(*converter);
      mode = identity_8bit ? mode_e::identity_8bit : mode_e::identity_10bit;
      BOOST_LOG(info)
        << "PLANK software identity input: planar GBR, codec depth="
        << (identity_8bit ? 8 : 10)
        << "-bit, CUDA readback depth=8-bit";
      if (mode == mode_e::identity_10bit) {
        start_workers();
      }
      return 0;
    }

    /**
     * @brief Apply identity GBR coefficients to the CUDA converter.
     */
    void apply_colorspace() override {
      if (mode == mode_e::identity_8bit ||
          mode == mode_e::identity_10bit ||
          mode == mode_e::yuv422_8bit ||
          mode == mode_e::yuv422_10bit) {
        sws.apply_colorspace(colorspace);
      }
    }

    /**
     * @brief Convert and read back one NvFBC CUDA image.
     *
     * @param img Captured NvFBC CUDA image.
     * @return 0 on success; -1 on CUDA or conversion failure.
     */
    int convert(platf::img_t &img) override {
      const auto conversion_start = std::chrono::steady_clock::now();
      auto &texture = static_cast<cuda::img_t &>(img).tex;
      if (mode == mode_e::identity_8bit || mode == mode_e::identity_10bit) {
        auto *base = reinterpret_cast<std::uint8_t *>(static_cast<std::uintptr_t>(device_compact));
        const auto plane_size = static_cast<std::size_t>(output_width) * output_height;
        const auto texture_object =
          (width != output_width || height != output_height) ? texture.texture.linear : texture.texture.point;
        if (sws.convert_yuv444(base, base + plane_size, base + plane_size * 2U, output_width, texture_object, stream.get())) {
          return -1;
        }
        CU_CHECK(cdf->cuMemcpyDtoHAsync(host_readback, device_compact, host_readback_size, stream.get()), "Couldn't read back compact identity planes");
      } else if (mode == mode_e::yuv422_8bit || mode == mode_e::yuv422_10bit) {
        auto *base = reinterpret_cast<std::uint8_t *>(static_cast<std::uintptr_t>(device_compact));
        const auto plane_size = static_cast<std::size_t>(output_width) * output_height;
        const auto bytes_per_sample = mode == mode_e::yuv422_10bit ? 2U : 1U;
        const auto luma_size = plane_size * bytes_per_sample;
        const auto chroma_size = (plane_size / 2U) * bytes_per_sample;
        const auto texture_object =
          (width != output_width || height != output_height) ? texture.texture.linear : texture.texture.point;
        const auto conversion_status = mode == mode_e::yuv422_10bit ?
          sws.convert_yuv422_10bit(base, base + luma_size, base + luma_size + chroma_size,
                                   output_width * 2U, output_width, texture_object, stream.get()) :
          sws.convert_yuv422(base, base + luma_size, base + luma_size + chroma_size,
                            output_width, output_width / 2U, texture_object, stream.get());
        if (conversion_status) {
          return -1;
        }
        CU_CHECK(cdf->cuMemcpyDtoHAsync(host_readback, device_compact, host_readback_size, stream.get()),
                 "Couldn't read back YUV422 planes");
      } else {
        return -1;
      }

      const auto synchronization_start = std::chrono::steady_clock::now();
      CU_CHECK(cdf->cuStreamSynchronize(stream.get()), "Couldn't synchronize software-encoder readback");
      const auto synchronization_end = std::chrono::steady_clock::now();
      dispatch_us.push_back(
        std::chrono::duration<double, std::micro>(synchronization_start - conversion_start).count()
      );
      readback_sync_us.push_back(
        std::chrono::duration<double, std::micro>(synchronization_end - synchronization_start).count()
      );
      if (mode == mode_e::identity_10bit) {
        const auto expansion_start = std::chrono::steady_clock::now();
        expand_10bit();
        depth_expansion_us.push_back(
          std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - expansion_start).count()
        );
      }
      total_conversion_us.push_back(
        std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - conversion_start).count()
      );
      return 0;
    }

  private:
    /**
     * @brief CUDA pinned-host allocation function loaded from the display driver.
     */
    using host_alloc_fn_t = CUresult(CUDAAPI *)(void **, std::size_t, unsigned int);

    /**
     * @brief CUDA pinned-host release function loaded from the display driver.
     */
    using host_free_fn_t = CUresult(CUDAAPI *)(void *);

    /**
     * @brief Active CUDA-to-software conversion mode.
     */
    enum class mode_e {
      unset,  ///< Frame format has not been attached.
      identity_8bit,  ///< Compact planar 8-bit identity GBR readback for libx264.
      identity_10bit,  ///< Compact identity GBR readback followed by CPU depth expansion.
      yuv422_8bit,  ///< CUDA Rec. 709 conversion to pinned planar 8-bit YUV 4:2:2.
      yuv422_10bit  ///< CUDA Rec. 709 conversion to pinned planar 10-bit YUV 4:2:2.
    };

    /**
     * @brief Start persistent workers used for 8-to-10-bit plane expansion.
     */
    void start_workers() {
      const auto available = std::max(1U, std::thread::hardware_concurrency());
      const auto worker_count = std::min(7U, available > 1U ? available - 1U : 0U);
      workers.reserve(worker_count);
      for (unsigned int index = 0; index < worker_count; ++index) {
        workers.emplace_back([this, index, worker_count](std::stop_token stop) {
          std::uint64_t observed_generation = 0;
          while (!stop.stop_requested()) {
            {
              std::unique_lock lock {work_mutex};
              work_ready.wait(lock, stop, [&]() {
                return generation != observed_generation;
              });
              if (stop.stop_requested()) {
                return;
              }
              observed_generation = generation;
            }

            expand_rows(index, worker_count + 1U);
            {
              std::lock_guard lock {work_mutex};
              if (--workers_pending == 0) {
                work_done.notify_one();
              }
            }
          }
        });
      }
    }

    /**
     * @brief Expand a strided share of compact 8-bit rows to full-range 10-bit.
     *
     * @param share_index Worker share index.
     * @param share_count Total worker and caller shares.
     */
    void expand_rows(unsigned int share_index, unsigned int share_count) {
      const auto *source = static_cast<const std::uint8_t *>(host_readback);
      for (std::size_t row = share_index; row < static_cast<std::size_t>(output_height) * 3U; row += share_count) {
        const auto plane = row / output_height;
        const auto plane_row = row % output_height;
        const auto *source_row = source + row * output_width;
        auto *destination_row = reinterpret_cast<std::uint16_t *>(frame->data[plane] + plane_row * frame->linesize[plane]);
        for (int x = 0; x < output_width; ++x) {
          destination_row[x] = video::expand_8bit_to_10bit(source_row[x]);
        }
      }
    }

    /**
     * @brief Expand all compact identity planes and wait for worker completion.
     *
     */
    void expand_10bit() {
      const auto worker_count = static_cast<unsigned int>(workers.size());
      {
        std::lock_guard lock {work_mutex};
        workers_pending = worker_count;
        ++generation;
      }
      work_ready.notify_all();
      expand_rows(worker_count, worker_count + 1U);

      if (worker_count != 0) {
        std::unique_lock lock {work_mutex};
        work_done.wait(lock, [&]() {
          return workers_pending == 0;
        });
      }
    }

    frame_t host_frame;  ///< Owned FFmpeg software frame.
    sws_t sws;  ///< CUDA identity-GBR converter.
    stream_t stream;  ///< CUDA conversion and readback stream.
    std::vector<std::jthread> workers;  ///< Persistent CPU depth-expansion workers.
    std::mutex work_mutex;  ///< Protects expansion generation and completion state.
    std::condition_variable_any work_ready;  ///< Signals a new compact frame to workers.
    std::condition_variable work_done;  ///< Signals completion of all worker shares.
    std::vector<double> dispatch_us;  ///< CUDA conversion/copy dispatch time before synchronization.
    std::vector<double> readback_sync_us;  ///< Wait for CUDA conversion and GPU-to-CPU readback completion.
    std::vector<double> depth_expansion_us;  ///< Exact compact 8-bit to 10-bit CPU expansion time.
    std::vector<double> total_conversion_us;  ///< Full CUDA software conversion and readback service time.
    std::uint64_t generation = 0;  ///< Current compact-frame expansion generation.
    unsigned int workers_pending = 0;  ///< Workers still expanding the current frame.
    CUdeviceptr device_compact = 0;  ///< Compact three-plane 8-bit CUDA surface.
    void *cuda_driver = nullptr;  ///< Dynamic CUDA driver handle for pinned-host APIs.
    host_alloc_fn_t host_alloc = nullptr;  ///< Pinned-host allocation entry point.
    host_free_fn_t host_free = nullptr;  ///< Pinned-host release entry point.
    void *host_readback = nullptr;  ///< Pinned native or compact host readback.
    std::size_t host_readback_size = 0;  ///< Pinned readback allocation size in bytes.
    int width = 0;  ///< NvFBC capture width.
    int height = 0;  ///< NvFBC capture height.
    int output_width = 0;  ///< Encoded frame width.
    int output_height = 0;  ///< Encoded frame height.
    int content_width = 0;  ///< Aspect-preserving scaled content width.
    int content_height = 0;  ///< Aspect-preserving scaled content height.
    int content_offset_x = 0;  ///< Horizontal letterbox offset in the encoded frame.
    int content_offset_y = 0;  ///< Vertical letterbox offset in the encoded frame.
    platf::pix_fmt_e capture_format = platf::pix_fmt_e::unknown;  ///< Negotiated software capture format.
    mode_e mode = mode_e::unset;  ///< Active readback and conversion mode.
  };

  /**
   * CUDA conversion surface registered directly with NVENC.
   */
  class cuda_nvenc_t final: public platf::nvenc_encode_device_t {
  public:
    ~cuda_nvenc_t() override {
      encoder.reset();
      nvenc = nullptr;
      if (native10_source && cdf) {
        CU_CHECK_IGNORE(cdf->cuMemFree(native10_source), "Couldn't free native X11 CUDA upload surface");
      }
      if (surface && cdf) {
        CU_CHECK_IGNORE(cdf->cuMemFree(surface), "Couldn't free direct NVENC surface");
      }
    }

    int init(int in_width, int in_height, platf::pix_fmt_e format) {
      if (!cdf) {
        BOOST_LOG(warning) << "cuda not initialized"sv;
        return -1;
      }

      input_width = in_width;
      input_height = in_height;
      buffer_format = format;

      CU_CHECK(cdf->cuCtxGetCurrent(&context), "Couldn't get current CUDA context");
      if (!context) {
        CU_CHECK(cdf->cuDeviceGet(&cuda_device, 0), "Couldn't get CUDA device");
        CU_CHECK(cdf->cuDevicePrimaryCtxRetain(&context, cuda_device), "Couldn't retain CUDA primary context");
        primary_context.device = cuda_device;
        primary_context.retained = true;
        CU_CHECK(cdf->cuCtxPushCurrent(context), "Couldn't select CUDA primary context");
        primary_context.pushed = true;
      }

      return 0;
    }

    int init_native10(int in_width, int in_height, platf::pix_fmt_e format) {
      if (init(in_width, in_height, format)) {
        return -1;
      }
      native10_input = true;
      return 0;
    }

    bool init_encoder(const ::video::config_t &client_config, const ::video::sunshine_colorspace_t &colorspace) override {
      output_width = client_config.width;
      output_height = client_config.height;
      const bool ten_bit = buffer_format == platf::pix_fmt_e::p010 || buffer_format == platf::pix_fmt_e::yuv444p16;
      const bool yuv444 = buffer_format == platf::pix_fmt_e::yuv444p || buffer_format == platf::pix_fmt_e::yuv444p16;
      if (buffer_format != platf::pix_fmt_e::nv12 && buffer_format != platf::pix_fmt_e::p010 && !yuv444) {
        BOOST_LOG(error) << "Direct CUDA NVENC does not support pixel format " << platf::from_pix_fmt(buffer_format);
        return false;
      }
      if (native10_input &&
          (buffer_format != platf::pix_fmt_e::yuv444p16 ||
           colorspace.colorspace != video::colorspace_e::identity_gbr ||
           colorspace.bit_depth != 10)) {
        BOOST_LOG(error) << "Native X11 direct NVENC requires 10-bit 4:4:4 identity input"sv;
        return false;
      }
      if (native10_input &&
          (output_width != input_width || output_height != input_height)) {
        BOOST_LOG(info) << "Native X11 direct NVENC CUDA scaling: "sv
                        << input_width << 'x' << input_height << " -> "sv
                        << output_width << 'x' << output_height;
      }

      const std::size_t row_bytes = static_cast<std::size_t>(output_width) * (ten_bit ? 2U : 1U);
      const std::size_t rows = static_cast<std::size_t>(output_height) * (yuv444 ? 3U : 3U) / (yuv444 ? 1U : 2U);
      std::size_t allocated_pitch = 0;
      if (check(cdf->cuMemAllocPitch(&surface, &allocated_pitch, row_bytes, rows, 16U), "Couldn't allocate direct NVENC surface: "sv)) {
        return false;
      }
      pitch = static_cast<std::uint32_t>(allocated_pitch);

      if (native10_input) {
        std::size_t source_pitch = 0;
        if (check(cdf->cuMemAllocPitch(&native10_source, &source_pitch,
                                       static_cast<std::size_t>(input_width) * 4U,
                                       input_height, 16U),
                  "Couldn't allocate native X11 CUDA upload surface: "sv)) {
          return false;
        }
        native10_source_pitch = static_cast<std::uint32_t>(source_pitch);
      }

      stream = make_stream();
      if (!stream) {
        return false;
      }
      if (!native10_input) {
        auto converter = sws_t::make(input_width, input_height, output_width, output_height, input_width * 4);
        if (!converter) {
          return false;
        }
        sws = std::move(*converter);
        sws.apply_colorspace(colorspace);
        if (sws.viewport.width < input_width || sws.viewport.height < input_height) {
          area_scaler = area_scaler_t::make(input_width, input_height, sws.viewport.width, sws.viewport.height);
          if (!area_scaler) {
            return false;
          }
          // The filtered texture already matches the content viewport. Keep its
          // letterbox offsets, but do not sample/resize it a second time.
          sws.scale = 1.0f;
          BOOST_LOG(info) << "NvFBC direct NVENC GPU area scaling: "sv
                          << input_width << 'x' << input_height << " -> "sv
                          << sws.viewport.width << 'x' << sws.viewport.height;
        }
      }

      encoder = ::nvenc::make_nvenc_cuda_encoder({
        context,
        static_cast<std::uintptr_t>(surface),
        pitch,
      });
      if (!encoder || !encoder->create_encoder(config::video.nv, client_config, colorspace, buffer_format)) {
        encoder.reset();
        return false;
      }
      nvenc = encoder.get();
      return true;
    }

    int convert(platf::img_t &img) override {
      auto *base = reinterpret_cast<std::uint8_t *>(static_cast<std::uintptr_t>(surface));
      int status = 0;
      if (native10_input) {
        if (!img.data || img.width != input_width || img.height != input_height ||
            img.pixel_pitch != 4 || img.row_pitch < input_width * 4) {
          BOOST_LOG(error) << "Native X11 direct NVENC received an incompatible packed RGB10 frame"sv;
          return -1;
        }
        CUDA_MEMCPY2D copy {};
        copy.srcMemoryType = CU_MEMORYTYPE_HOST;
        copy.srcHost = img.data;
        copy.srcPitch = static_cast<std::size_t>(img.row_pitch);
        copy.dstMemoryType = CU_MEMORYTYPE_DEVICE;
        copy.dstDevice = native10_source;
        copy.dstPitch = native10_source_pitch;
        copy.WidthInBytes = static_cast<std::size_t>(input_width) * 4U;
        copy.Height = input_height;
        CU_CHECK(cdf->cuMemcpy2DAsync(&copy, stream.get()),
                 "Couldn't upload native X11 RGB10 frame");
        status = scale_xrgb10_to_yuv444_10bit(
          static_cast<std::uintptr_t>(native10_source), native10_source_pitch,
          input_width, input_height, base, base + pitch * output_height,
          base + pitch * output_height * 2, pitch,
          output_width, output_height, stream.get());
      } else {
        auto &texture = static_cast<cuda::img_t &>(img).tex;
        auto source = texture.texture.point;
        if (area_scaler) {
          status = area_scaler->resize(source, stream.get());
          if (status) {
            return status;
          }
          source = area_scaler->texture();
        }
        if (buffer_format == platf::pix_fmt_e::nv12) {
          status = sws.convert_nv12(base, base + pitch * output_height, pitch, pitch, source, stream.get());
        } else if (buffer_format == platf::pix_fmt_e::p010) {
          status = sws.convert_p010(base, base + pitch * output_height, pitch, pitch, source, stream.get());
        } else if (buffer_format == platf::pix_fmt_e::yuv444p16) {
          status = sws.convert_yuv444_10bit(base, base + pitch * output_height, base + pitch * output_height * 2, pitch, source, stream.get());
        } else {
          status = sws.convert_yuv444(base, base + pitch * output_height, base + pitch * output_height * 2, pitch, source, stream.get());
        }
      }
      if (status) {
        return status;
      }
      CU_CHECK(cdf->cuStreamSynchronize(stream.get()), "Couldn't synchronize direct NVENC conversion");
      return 0;
    }

  private:
    struct primary_context_t {
      ~primary_context_t() {
        if (retained && cdf) {
          if (pushed) {
            CUcontext popped = nullptr;
            CU_CHECK_IGNORE(cdf->cuCtxPopCurrent(&popped), "Couldn't pop CUDA primary context");
          }
          CU_CHECK_IGNORE(cdf->cuDevicePrimaryCtxRelease(device), "Couldn't release CUDA primary context");
        }
      }
      CUdevice device = 0;
      bool retained = false;
      bool pushed = false;
    } primary_context;

    std::unique_ptr<::nvenc::nvenc_encoder> encoder;
    sws_t sws;
    std::unique_ptr<area_scaler_t> area_scaler;
    stream_t stream;
    CUcontext context = nullptr;
    CUdeviceptr surface = 0;
    CUdeviceptr native10_source = 0;
    CUdevice cuda_device = 0;
    std::uint32_t pitch = 0;
    std::uint32_t native10_source_pitch = 0;
    int input_width = 0;
    int input_height = 0;
    int output_width = 0;
    int output_height = 0;
    platf::pix_fmt_e buffer_format = platf::pix_fmt_e::unknown;
    bool native10_input = false;
  };

  /**
   * @brief Opens the DRM device associated with the CUDA device index.
   * @param index CUDA device index to open.
   * @return File descriptor or -1 on failure.
   */
  file_t open_drm_fd_for_cuda_device(int index) {
    CUdevice device;
    CU_CHECK(cdf->cuDeviceGet(&device, index), "Couldn't get CUDA device");

    // There's no way to directly go from CUDA to a DRM device, so we'll
    // use sysfs to look up the DRM device name from the PCI ID.
    std::array<char, 13> pci_bus_id;
    CU_CHECK(cdf->cuDeviceGetPCIBusId(pci_bus_id.data(), pci_bus_id.size(), device), "Couldn't get CUDA device PCI bus ID");
    BOOST_LOG(debug) << "Found CUDA device with PCI bus ID: "sv << pci_bus_id.data();

    // Linux uses lowercase hexadecimal while CUDA uses uppercase
    std::transform(pci_bus_id.begin(), pci_bus_id.end(), pci_bus_id.begin(), [](char c) {
      return std::tolower(c);
    });

    // Look for the name of the primary node in sysfs
    try {
      char sysfs_path[PATH_MAX];
      std::snprintf(sysfs_path, sizeof(sysfs_path), "/sys/bus/pci/devices/%s/drm", pci_bus_id.data());
      fs::path sysfs_dir {sysfs_path};
      for (auto &entry : fs::directory_iterator {sysfs_dir}) {
        auto file = entry.path().filename();
        auto filestring = file.generic_string();
        if (std::string_view {filestring}.substr(0, 4) != "card"sv) {
          continue;
        }

        BOOST_LOG(debug) << "Found DRM primary node: "sv << filestring;

        fs::path dri_path {"/dev/dri"sv};
        auto device_path = dri_path / file;
        return platf::open_drm_card_fd(device_path);
      }
    } catch (const std::filesystem::filesystem_error &err) {
      BOOST_LOG(error) << "Failed to read sysfs: "sv << err.what();
    }

    BOOST_LOG(error) << "Unable to find DRM device with PCI bus ID: "sv << pci_bus_id.data();
    return -1;
  }

  /**
   * @brief CUDA frame resources registered for interop conversion.
   */
  struct cu_resources {
    registered_resource_t y_res;  ///< Y res.
    registered_resource_t u_res;  ///< U res.
    registered_resource_t v_res;  ///< V res.
    registered_resource_t uv_res;  ///< Uv res.
  };

  /**
   * @brief OpenGL/CUDA interop resources used for GPU-side frame conversion.
   */
  class gl_cuda_vram_t: public platf::avcodec_encode_device_t {
  public:
    /**
     * @brief Initialize the GL->CUDA encoding device.
     * @param in_width Width of captured frames.
     * @param in_height Height of captured frames.
     * @param offset_x Offset of content in captured frame.
     * @param offset_y Offset of content in captured frame.
     * @return 0 on success or -1 on failure.
     */
    int init(int in_width, int in_height, int offset_x, int offset_y) {
      // This must be non-zero to tell the video core that it's a hardware encoding device.
      data = (void *) 0x1;

      // TODO: Support more than one CUDA device
      file = std::move(open_drm_fd_for_cuda_device(0));
      if (file.el < 0) {
        char string[1024];
        BOOST_LOG(error) << "Couldn't open DRM FD for CUDA device: "sv << strerror_r(errno, string, sizeof(string));
        return -1;
      }

      gbm.reset(gbm::create_device(file.el));
      if (!gbm) {
        BOOST_LOG(error) << "Couldn't create GBM device: ["sv << util::hex(eglGetError()).to_string_view() << ']';
        return -1;
      }

      display = egl::make_display(gbm.get());
      if (!display) {
        return -1;
      }

      auto ctx_opt = egl::make_ctx(display.get());
      if (!ctx_opt) {
        return -1;
      }

      ctx = std::move(*ctx_opt);

      width = in_width;
      height = in_height;

      sequence = 0;

      this->offset_x = offset_x;
      this->offset_y = offset_y;

      return 0;
    }

    /**
     * @brief Initialize color conversion into target CUDA frame.
     * @param frame Destination CUDA frame to write into.
     * @param hw_frames_ctx_buf FFmpeg hardware frame context.
     * @return 0 on success or -1 on failure.
     */
    int set_frame(AVFrame *frame, AVBufferRef *hw_frames_ctx_buf) override {
      this->hwframe.reset(frame);
      this->frame = frame;

      auto hw_frames_ctx = (AVHWFramesContext *) hw_frames_ctx_buf->data;

      if (hw_frames_ctx->sw_format != AV_PIX_FMT_NV12 && hw_frames_ctx->sw_format != AV_PIX_FMT_YUV444P && hw_frames_ctx->sw_format != AV_PIX_FMT_P010LE && hw_frames_ctx->sw_format != AV_PIX_FMT_YUV444P16LE) {
        BOOST_LOG(error) << "cuda::gl_cuda_vram_t doesn't support any format other than AV_PIX_FMT_NV12, AV_PIX_FMT_P010LE, AV_PIX_FMT_YUV444P and AV_PIX_FMT_YUV444P16LE"sv;
        return -1;
      }

      if (!frame->buf[0]) {
        if (av_hwframe_get_buffer(hw_frames_ctx_buf, frame, 0)) {
          BOOST_LOG(error) << "Couldn't get hwframe for NVENC_GL"sv;
          return -1;
        }
      }

      sw_format = hw_frames_ctx->sw_format;
      is_yuv444 = (sw_format == AV_PIX_FMT_YUV444P || sw_format == AV_PIX_FMT_YUV444P16LE);

      auto sws_opt = egl::sws_t::make(width, height, frame->width, frame->height, sw_format, is_yuv444);
      if (!sws_opt) {
        return -1;
      }

      this->sws = std::move(*sws_opt);

      if (is_yuv444) {
        auto yuv444_opt = egl::create_yuv444_target(frame->width, frame->height, sw_format);
        if (!yuv444_opt) {
          return -1;
        }
        this->yuv444 = std::move(*yuv444_opt);
      } else {
        auto nv12_opt = egl::create_nv12_target(frame->width, frame->height, sw_format);
        if (!nv12_opt) {
          return -1;
        }
        this->nv12 = std::move(*nv12_opt);
      }

      auto cuda_ctx = (AVCUDADeviceContext *) hw_frames_ctx->device_ctx->hwctx;

      stream = make_stream();
      if (!stream) {
        return -1;
      }

      cuda_ctx->stream = stream.get();

      if (is_yuv444) {
        CU_CHECK(cdf->cuGraphicsGLRegisterImage(&cu_res.y_res, yuv444->tex[0], GL_TEXTURE_2D, CU_GRAPHICS_REGISTER_FLAGS_READ_ONLY), "Couldn't register Y texture");
        CU_CHECK(cdf->cuGraphicsGLRegisterImage(&cu_res.u_res, yuv444->tex[1], GL_TEXTURE_2D, CU_GRAPHICS_REGISTER_FLAGS_READ_ONLY), "Couldn't register U texture");
        CU_CHECK(cdf->cuGraphicsGLRegisterImage(&cu_res.v_res, yuv444->tex[2], GL_TEXTURE_2D, CU_GRAPHICS_REGISTER_FLAGS_READ_ONLY), "Couldn't register V texture");
      } else {
        CU_CHECK(cdf->cuGraphicsGLRegisterImage(&cu_res.y_res, nv12->tex[0], GL_TEXTURE_2D, CU_GRAPHICS_REGISTER_FLAGS_READ_ONLY), "Couldn't register Y plane texture");
        CU_CHECK(cdf->cuGraphicsGLRegisterImage(&cu_res.uv_res, nv12->tex[1], GL_TEXTURE_2D, CU_GRAPHICS_REGISTER_FLAGS_READ_ONLY), "Couldn't register UV plane texture");
      }
      return 0;
    }

    /**
     * @brief Convert the captured image into the target CUDA frame.
     * @param img Captured screen image.
     * @return 0 on success or -1 on failure.
     */
    int convert(platf::img_t &img) override {
      auto &descriptor = (egl::img_descriptor_t &) img;

      if (descriptor.sequence == 0) {
        // For dummy images, use a blank RGB texture instead of importing a DMA-BUF
        rgb = egl::create_blank(img);
      } else if (descriptor.sequence > sequence) {
        sequence = descriptor.sequence;

        rgb = egl::rgb_t {};

        auto rgb_opt = egl::import_source(display.get(), descriptor.sd);

        if (!rgb_opt) {
          return -1;
        }

        rgb = std::move(*rgb_opt);
      }

      auto fmt_desc = av_pix_fmt_desc_get(sw_format);

      sws.load_vram(descriptor, offset_x, offset_y, rgb->tex[0], is_yuv444);

      if (is_yuv444) {
        // Perform the color conversion and scaling in GL
        sws.convert_yuv444(yuv444->buf);

        // Map the GL textures to read for CUDA
        std::array<CUgraphicsResource, 3> resources = {{cu_res.y_res.get(), cu_res.u_res.get(), cu_res.v_res.get()}};
        CU_CHECK(cdf->cuGraphicsMapResources(resources.size(), resources.data(), stream.get()), "Couldn't map GL textures in CUDA");

        // Copy from the GL textures to the target CUDA frame
        for (int i = 0; i < 3; i++) {
          CUDA_MEMCPY2D cpy = {};
          cpy.srcMemoryType = CU_MEMORYTYPE_ARRAY;
          CU_CHECK(cdf->cuGraphicsSubResourceGetMappedArray(&cpy.srcArray, resources[i], 0, 0), "Couldn't get mapped plane array");

          cpy.dstMemoryType = CU_MEMORYTYPE_DEVICE;
          cpy.dstDevice = (CUdeviceptr) frame->data[i];
          cpy.dstPitch = frame->linesize[i];
          cpy.WidthInBytes = (frame->width * fmt_desc->comp[i].step);
          cpy.Height = frame->height;

          CU_CHECK_IGNORE(cdf->cuMemcpy2DAsync(&cpy, stream.get()), "Couldn't copy texture to CUDA frame");
        }
        // Unmap the textures to allow modification from GL again
        CU_CHECK(cdf->cuGraphicsUnmapResources(resources.size(), resources.data(), stream.get()), "Couldn't unmap GL textures from CUDA");

      } else {
        // Perform the color conversion and scaling in GL
        sws.convert_nv12(nv12->buf);

        // Map the GL textures to read for CUDA
        std::array<CUgraphicsResource, 2> resources = {{cu_res.y_res.get(), cu_res.uv_res.get()}};
        CU_CHECK(cdf->cuGraphicsMapResources(resources.size(), resources.data(), stream.get()), "Couldn't map GL textures in CUDA");

        // Copy from the GL textures to the target CUDA frame
        for (int i = 0; i < 2; i++) {
          CUDA_MEMCPY2D cpy = {};
          cpy.srcMemoryType = CU_MEMORYTYPE_ARRAY;
          CU_CHECK(cdf->cuGraphicsSubResourceGetMappedArray(&cpy.srcArray, resources[i], 0, 0), "Couldn't get mapped plane array");

          cpy.dstMemoryType = CU_MEMORYTYPE_DEVICE;
          cpy.dstDevice = (CUdeviceptr) frame->data[i];
          cpy.dstPitch = frame->linesize[i];
          cpy.WidthInBytes = (frame->width * fmt_desc->comp[i].step) >> (i ? fmt_desc->log2_chroma_w : 0);
          cpy.Height = frame->height >> (i ? fmt_desc->log2_chroma_h : 0);

          CU_CHECK_IGNORE(cdf->cuMemcpy2DAsync(&cpy, stream.get()), "Couldn't copy texture to CUDA frame");
        }
        // Unmap the textures to allow modification from GL again
        CU_CHECK(cdf->cuGraphicsUnmapResources(resources.size(), resources.data(), stream.get()), "Couldn't unmap GL textures from CUDA");
      }

      return 0;
    }

    /**
     * @brief Configures shader parameters for the specified colorspace.
     */
    void apply_colorspace() override {
      sws.apply_colorspace(colorspace, is_yuv444);
    }

    file_t file;  ///< File descriptor for the imported DMA-BUF.
    gbm::gbm_t gbm;  ///< GBM device used for buffer allocation..
    egl::display_t display;  ///< EGL display used to import captured frames.
    egl::ctx_t ctx;  ///< EGL context used to import captured frames.

    // This must be destroyed before display_t
    stream_t stream;  ///< CUDA stream used for asynchronous conversion work.
    frame_t hwframe;  ///< FFmpeg hardware frame backed by CUDA resources.

    egl::sws_t sws;  ///< Software scaler used for CUDA frame conversion fallback paths.
    egl::nv12_t nv12;  ///< EGL/OpenGL resources used for NV12 output frames.
    egl::yuv444_t yuv444;  ///< EGL/OpenGL resources used for YUV444 output frames.
    AVPixelFormat sw_format;  ///< FFmpeg software pixel format produced by conversion.

    int height;  ///< Frame or display height in pixels.
    int width;  ///< Frame or display width in pixels.

    std::uint64_t sequence;  ///< Capture sequence number associated with the frame.
    egl::rgb_t rgb;  ///< Imported RGB source image used before CUDA conversion.

    cu_resources cu_res;  ///< CUDA graphics resources registered for the current frame.

    int offset_x;  ///< Horizontal offset in physical pixels.
    int offset_y;  ///< Vertical offset in physical pixels.

    bool is_yuv444;  ///< Whether the CUDA converter outputs YUV 4:4:4.
  };

  /**
   * @brief Create AVCodec encode device.
   *
   * @param width Frame or display width in pixels.
   * @param height Frame or display height in pixels.
   * @param vram Whether the image should use GPU memory instead of system memory.
   * @return Constructed AVCodec encode device object.
   */
  std::unique_ptr<platf::avcodec_encode_device_t> make_avcodec_encode_device(int width, int height, bool vram) {
    if (init()) {
      return nullptr;
    }

    std::unique_ptr<cuda_t> cuda;

    if (vram) {
      cuda = std::make_unique<cuda_vram_t>();
    } else {
      cuda = std::make_unique<cuda_ram_t>();
    }

    if (cuda->init(width, height)) {
      return nullptr;
    }

    return cuda;
  }

  std::unique_ptr<platf::avcodec_encode_device_t> make_avcodec_software_encode_device(int width, int height, platf::pix_fmt_e pix_fmt) {
    if (init()) {
      return nullptr;
    }

    auto device = std::make_unique<cuda_software_t>();
    if (device->init(width, height, pix_fmt)) {
      return nullptr;
    }
    return device;
  }

  std::unique_ptr<platf::nvenc_encode_device_t> make_nvenc_encode_device(int width, int height, platf::pix_fmt_e pix_fmt) {
    if (init()) {
      return nullptr;
    }

    auto device = std::make_unique<cuda_nvenc_t>();
    if (device->init(width, height, pix_fmt)) {
      return nullptr;
    }
    return device;
  }

  std::unique_ptr<platf::nvenc_encode_device_t> make_nvenc_native10_encode_device(int width, int height, platf::pix_fmt_e pix_fmt) {
    if (init()) {
      return nullptr;
    }

    auto device = std::make_unique<cuda_nvenc_t>();
    if (device->init_native10(width, height, pix_fmt)) {
      return nullptr;
    }
    return device;
  }

  /**
   * @brief Create a GL->CUDA encoding device for consuming captured dmabufs.
   * @param width Width of captured frames.
   * @param height Height of captured frames.
   * @param offset_x Offset of content in captured frame.
   * @param offset_y Offset of content in captured frame.
   * @return FFmpeg encoding device context.
   */
  std::unique_ptr<platf::avcodec_encode_device_t> make_avcodec_gl_encode_device(int width, int height, int offset_x, int offset_y) {
    if (init()) {
      return nullptr;
    }

    auto cuda = std::make_unique<gl_cuda_vram_t>();

    if (cuda->init(width, height, offset_x, offset_y)) {
      return nullptr;
    }

    return cuda;
  }

  namespace nvfbc {
    static PNVFBCCREATEINSTANCE createInstance {};
    static NVFBC_API_FUNCTION_LIST func {NVFBC_VERSION};

    static constexpr inline NVFBC_BOOL nv_bool(bool b) {
      return b ? NVFBC_TRUE : NVFBC_FALSE;
    }

    static void *handle {nullptr};

    /**
     * @brief Load NvFBC and create the CUDA capture helper.
     *
     * @return 0 on success; nonzero or negative platform status on failure.
     */
    int init() {
      static bool funcs_loaded = false;

      if (funcs_loaded) {
        return 0;
      }

      if (!handle) {
        handle = dyn::handle({"libnvidia-fbc.so.1", "libnvidia-fbc.so"});
        if (!handle) {
          return -1;
        }
      }

      std::vector<std::tuple<dyn::apiproc *, const char *>> funcs {
        {(dyn::apiproc *) &createInstance, "NvFBCCreateInstance"},
      };

      if (dyn::load(handle, funcs)) {
        dlclose(handle);
        handle = nullptr;

        return -1;
      }

      auto status = cuda::nvfbc::createInstance(&cuda::nvfbc::func);
      if (status) {
        BOOST_LOG(error) << "Unable to create NvFBC instance"sv;

        dlclose(handle);
        handle = nullptr;
        return -1;
      }

      funcs_loaded = true;
      return 0;
    }

    /**
     * @brief NvFBC CUDA context selected for a capture session.
     */
    class ctx_t {
    public:
      /**
       * @brief Create an NvFBC session context for a native capture handle.
       *
       * @param handle Native library or object handle used by the operation.
       */
      ctx_t(NVFBC_SESSION_HANDLE handle):
          handle {handle} {
        NVFBC_BIND_CONTEXT_PARAMS params {NVFBC_BIND_CONTEXT_PARAMS_VER};

        if (func.nvFBCBindContext(handle, &params)) {
          BOOST_LOG(error) << "Couldn't bind NvFBC context to current thread: " << func.nvFBCGetLastErrorStr(handle);
        } else {
          bound = true;
        }
      }

      ~ctx_t() {
        if (!bound) {
          return;
        }

        NVFBC_RELEASE_CONTEXT_PARAMS params {NVFBC_RELEASE_CONTEXT_PARAMS_VER};
        if (func.nvFBCReleaseContext(handle, &params)) {
          BOOST_LOG(error) << "Couldn't release NvFBC context from current thread: " << func.nvFBCGetLastErrorStr(handle);
        }
      }

      /**
       * @brief Mark the context as released by an operation that invalidated the handle.
       */
      void disarm() {
        bound = false;
      }

      NVFBC_SESSION_HANDLE handle;  ///< NVIDIA FBC capture session handle.
      bool bound {};  ///< Whether this object owns a context binding to release.
    };

    /**
     * @brief NvFBC dynamic-library handle and function table.
     */
    class handle_t {
      enum flag_e {
        SESSION_HANDLE,
        SESSION_CAPTURE,
        MAX_FLAGS,
      };

    public:
      handle_t() = default;

      /**
       * @brief Move an NvFBC API handle and its resolved function table.
       *
       * @param other Source object whose state is copied or moved into this object.
       */
      handle_t(handle_t &&other):
          handle_flags {other.handle_flags},
          handle {other.handle} {
        other.handle_flags.reset();
      }

      /**
       * @brief Assign state from another instance while preserving ownership semantics.
       *
       * @param other Source object whose state is copied or moved into this object.
       * @return Reference or value produced by the operator.
       */
      handle_t &operator=(handle_t &&other) {
        std::swap(handle_flags, other.handle_flags);
        std::swap(handle, other.handle);

        return *this;
      }

      /**
       * @brief Allocate the underlying object and wrap it in the owning handle.
       *
       * @return Created backend object, or null when creation fails.
       */
      static std::optional<handle_t> make() {
        NVFBC_CREATE_HANDLE_PARAMS params {NVFBC_CREATE_HANDLE_PARAMS_VER};

        // Set privateData to allow NvFBC on consumer NVIDIA GPUs.
        // Based on https://github.com/keylase/nvidia-patch/blob/3193b4b1cea91527bf09ea9b8db5aade6a3f3c0a/win/nvfbcwrp/nvfbcwrp_main.cpp#L23-L25 .
        const unsigned int MAGIC_PRIVATE_DATA[4] = {0xAEF57AC5, 0x401D1A39, 0x1B856BBE, 0x9ED0CEBA};
        params.privateData = MAGIC_PRIVATE_DATA;
        params.privateDataSize = sizeof(MAGIC_PRIVATE_DATA);

        handle_t handle;
        auto status = func.nvFBCCreateHandle(&handle.handle, &params);
        if (status) {
          BOOST_LOG(error) << "Failed to create session: "sv << handle.last_error();

          return std::nullopt;
        }

        handle.handle_flags[SESSION_HANDLE] = true;

        return handle;
      }

      /**
       * @brief Read the last error string from the active NvFBC session.
       *
       * @return Human-readable NvFBC error string.
       */
      const char *last_error() {
        return func.nvFBCGetLastErrorStr(handle);
      }

      /**
       * @brief Return or update the current status value.
       *
       * @return Status status.
       */
      std::optional<NVFBC_GET_STATUS_PARAMS> status() {
        NVFBC_GET_STATUS_PARAMS params {NVFBC_GET_STATUS_PARAMS_VER};

        auto status = func.nvFBCGetStatus(handle, &params);
        if (status) {
          BOOST_LOG(error) << "Failed to get NvFBC status: "sv << last_error();

          return std::nullopt;
        }

        return params;
      }

      /**
       * @brief Run the capture loop for this backend.
       *
       * @param capture_params Capture params.
       * @return Capture status reported to the streaming pipeline.
       */
      int capture(NVFBC_CREATE_CAPTURE_SESSION_PARAMS &capture_params) {
        if (func.nvFBCCreateCaptureSession(handle, &capture_params)) {
          BOOST_LOG(error) << "Failed to start capture session: "sv << last_error();
          return -1;
        }

        handle_flags[SESSION_CAPTURE] = true;

        NVFBC_TOCUDA_SETUP_PARAMS setup_params {
          NVFBC_TOCUDA_SETUP_PARAMS_VER,
          NVFBC_BUFFER_FORMAT_BGRA,
        };

        if (func.nvFBCToCudaSetUp(handle, &setup_params)) {
          BOOST_LOG(error) << "Failed to setup cuda interop with nvFBC: "sv << last_error();
          return -1;
        }
        return 0;
      }

      /**
       * @brief Release the NvFBC capture session and wait for capture work to stop.
       *
       * @return Stop status.
       */
      int stop() {
        if (!handle_flags[SESSION_CAPTURE]) {
          return 0;
        }

        NVFBC_DESTROY_CAPTURE_SESSION_PARAMS params {NVFBC_DESTROY_CAPTURE_SESSION_PARAMS_VER};

        if (func.nvFBCDestroyCaptureSession(handle, &params)) {
          BOOST_LOG(error) << "Couldn't destroy capture session: "sv << last_error();

          return -1;
        }

        handle_flags[SESSION_CAPTURE] = false;

        return 0;
      }

      /**
       * @brief Reset the object to its initial empty state.
       *
       * @return Reset status.
       */
      int reset() {
        if (!handle_flags[SESSION_HANDLE]) {
          return 0;
        }

        stop();

        NVFBC_DESTROY_HANDLE_PARAMS params {NVFBC_DESTROY_HANDLE_PARAMS_VER};

        ctx_t ctx {handle};
        if (func.nvFBCDestroyHandle(handle, &params)) {
          BOOST_LOG(error) << "Couldn't destroy session handle: "sv << func.nvFBCGetLastErrorStr(handle);
        } else {
          // NvFBCDestroyHandle() implicitly releases the context and invalidates
          // the handle, so ctx must not call NvFBCReleaseContext() afterward.
          ctx.disarm();
        }

        handle_flags[SESSION_HANDLE] = false;

        return 0;
      }

      ~handle_t() {
        reset();
      }

      std::bitset<MAX_FLAGS> handle_flags;  ///< Handle flags.

      NVFBC_SESSION_HANDLE handle;  ///< NVIDIA FBC capture session handle.
    };

    /**
     * @brief NvFBC display capture backend that produces CUDA frames.
     */
    class display_t: public platf::display_t {
    public:
      /**
       * @brief Initialize NvFBC capture for the selected display.
       *
       * @param display_name Display name.
       * @param config Configuration values to apply.
       * @return 0 on success; nonzero or negative platform status on failure.
       */
      int init(const std::string_view &display_name, const ::video::config_t &config) {
        auto handle = handle_t::make();
        if (!handle) {
          return -1;
        }

        ctx_t ctx {handle->handle};

        auto status_params = handle->status();
        if (!status_params) {
          return -1;
        }

        int streamedMonitor = -1;
        if (!display_name.empty()) {
          if (status_params->bXRandRAvailable) {
            int monitor_nr = -1;
            const auto [end, error] = std::from_chars(
              display_name.data(), display_name.data() + display_name.size(), monitor_nr
            );
            const bool numeric_name = error == std::errc {} && end == display_name.data() + display_name.size();
            if (!numeric_name) {
              for (std::uint32_t index = 0; index < status_params->dwOutputNum; ++index) {
                if (display_name == status_params->outputs[index].name) {
                  monitor_nr = static_cast<int>(index);
                  break;
                }
              }
            }

            if (monitor_nr < 0 || monitor_nr >= status_params->dwOutputNum) {
              BOOST_LOG(warning) << "Can't stream monitor ["sv << display_name << "], defaulting to virtual desktop"sv;
            } else {
              streamedMonitor = monitor_nr;
            }
          } else {
            BOOST_LOG(warning) << "XrandR not available, streaming entire virtual desktop"sv;
          }
        }

        delay = ::video::capture_frame_interval(config);

        capture_params = NVFBC_CREATE_CAPTURE_SESSION_PARAMS {NVFBC_CREATE_CAPTURE_SESSION_PARAMS_VER};

        capture_params.eCaptureType = NVFBC_CAPTURE_SHARED_CUDA;
        capture_params.bDisableAutoModesetRecovery = nv_bool(true);

        capture_params.dwSamplingRateMs = 1000 /* ms */ / config.framerate;

        if (streamedMonitor != -1) {
          auto &output = status_params->outputs[streamedMonitor];

          width = output.trackedBox.w;
          height = output.trackedBox.h;
          offset_x = output.trackedBox.x;
          offset_y = output.trackedBox.y;

          capture_params.eTrackingType = NVFBC_TRACKING_OUTPUT;
          capture_params.dwOutputId = output.dwId;
        } else {
          capture_params.eTrackingType = NVFBC_TRACKING_SCREEN;

          width = status_params->screenSize.w;
          height = status_params->screenSize.h;
        }

        env_width = status_params->screenSize.w;
        env_height = status_params->screenSize.h;

        this->handle = std::move(*handle);
        return 0;
      }

      platf::capture_e capture(const push_captured_image_cb_t &push_captured_image_cb, const pull_free_image_cb_t &pull_free_image_cb, bool *cursor) override {
        auto next_frame = std::chrono::steady_clock::now();

        {
          // We must create at least one texture on this thread before calling NvFBCToCudaSetUp()
          // Otherwise it fails with "Unable to register an OpenGL buffer to a CUDA resource (result: 201)" message
          std::shared_ptr<platf::img_t> img_dummy;
          pull_free_image_cb(img_dummy);
        }

        // Force display_t::capture to initialize handle_t::capture
        cursor_visible = !*cursor;

        ctx_t ctx {handle.handle};
        auto fg = util::fail_guard([&]() {
          handle.reset();
        });

        sleep_overshoot_logger.reset();

        while (true) {
          auto now = std::chrono::steady_clock::now();
          if (next_frame > now) {
            std::this_thread::sleep_for(next_frame - now);
            sleep_overshoot_logger.first_point(next_frame);
            sleep_overshoot_logger.second_point_now_and_log();
          }

          next_frame += delay;
          if (next_frame < now) {  // some major slowdown happened; we couldn't keep up
            next_frame = now + delay;
          }

          std::shared_ptr<platf::img_t> img_out;
          auto status = snapshot(pull_free_image_cb, img_out, 150ms, *cursor);
          switch (status) {
            case platf::capture_e::reinit:
            case platf::capture_e::error:
            case platf::capture_e::interrupted:
              return status;
            case platf::capture_e::timeout:
              if (!push_captured_image_cb(std::move(img_out), false)) {
                return platf::capture_e::ok;
              }
              break;
            case platf::capture_e::ok:
              if (!push_captured_image_cb(std::move(img_out), true)) {
                return platf::capture_e::ok;
              }
              break;
            default:
              BOOST_LOG(error) << "Unrecognized capture status ["sv << (int) status << ']';
              return status;
          }
        }

        return platf::capture_e::ok;
      }

      // Reinitialize the capture session.
      /**
       * @brief Reinitialize NvFBC capture after a recoverable failure.
       *
       * @param cursor Cursor image or visibility state to composite.
       * @return Reinit status.
       */
      platf::capture_e reinit(bool cursor) {
        if (handle.stop()) {
          return platf::capture_e::error;
        }

        cursor_visible = cursor;
        if (cursor) {
          capture_params.bPushModel = nv_bool(false);
          capture_params.bWithCursor = nv_bool(true);
          capture_params.bAllowDirectCapture = nv_bool(false);
        } else {
          capture_params.bPushModel = nv_bool(true);
          capture_params.bWithCursor = nv_bool(false);
          capture_params.bAllowDirectCapture = nv_bool(true);
        }

        if (handle.capture(capture_params)) {
          return platf::capture_e::error;
        }

        // If trying to capture directly, test if it actually does.
        if (capture_params.bAllowDirectCapture) {
          CUdeviceptr device_ptr;
          NVFBC_FRAME_GRAB_INFO info;

          NVFBC_TOCUDA_GRAB_FRAME_PARAMS grab {
            NVFBC_TOCUDA_GRAB_FRAME_PARAMS_VER,
            NVFBC_TOCUDA_GRAB_FLAGS_NOWAIT,
            &device_ptr,
            &info,
            0,
          };

          // Direct Capture may fail the first few times, even if it's possible
          for (int x = 0; x < 3; ++x) {
            if (auto status = func.nvFBCToCudaGrabFrame(handle.handle, &grab)) {
              if (status == NVFBC_ERR_MUST_RECREATE) {
                return platf::capture_e::reinit;
              }

              BOOST_LOG(error) << "Couldn't capture nvFramebuffer: "sv << handle.last_error();

              return platf::capture_e::error;
            }

            if (info.bDirectCapture) {
              break;
            }

            BOOST_LOG(debug) << "Direct capture failed attempt ["sv << x << ']';
          }

          if (!info.bDirectCapture) {
            BOOST_LOG(debug) << "Direct capture failed, trying the extra copy method"sv;
            // Direct capture failed
            capture_params.bPushModel = nv_bool(false);
            capture_params.bWithCursor = nv_bool(false);
            capture_params.bAllowDirectCapture = nv_bool(false);

            if (handle.stop() || handle.capture(capture_params)) {
              return platf::capture_e::error;
            }
          }
        }

        return platf::capture_e::ok;
      }

      /**
       * @brief Capture a display frame into the provided image object.
       *
       * @param pull_free_image_cb Callback that provides an available image buffer.
       * @param img_out Captured CUDA image returned to the streaming pipeline.
       * @param timeout Maximum time to wait for the operation.
       * @param cursor Cursor image or visibility state to composite.
       * @return Capture status reported to the streaming pipeline.
       */
      platf::capture_e snapshot(const pull_free_image_cb_t &pull_free_image_cb, std::shared_ptr<platf::img_t> &img_out, std::chrono::milliseconds timeout, bool cursor) {
        if (cursor != cursor_visible) {
          auto status = reinit(cursor);
          if (status != platf::capture_e::ok) {
            return status;
          }
        }

        CUdeviceptr device_ptr;
        NVFBC_FRAME_GRAB_INFO info;

        NVFBC_TOCUDA_GRAB_FRAME_PARAMS grab {
          NVFBC_TOCUDA_GRAB_FRAME_PARAMS_VER,
          NVFBC_TOCUDA_GRAB_FLAGS_NOWAIT,
          &device_ptr,
          &info,
          (std::uint32_t) timeout.count(),
        };

        if (auto status = func.nvFBCToCudaGrabFrame(handle.handle, &grab)) {
          if (status == NVFBC_ERR_MUST_RECREATE) {
            return platf::capture_e::reinit;
          }

          BOOST_LOG(error) << "Couldn't capture nvFramebuffer: "sv << handle.last_error();
          return platf::capture_e::error;
        }

        if (!pull_free_image_cb(img_out)) {
          return platf::capture_e::interrupted;
        }
        auto img = (img_t *) img_out.get();

        // NvFBC reports CLOCK_MONOTONIC microseconds for the time the display
        // server started rendering a new frame. Preserve it so the streaming
        // protocol can report capture-to-packet processing latency. Repeated
        // frames retain the old driver timestamp and must remain untimestamped.
        if (info.bIsNewFrame && info.ulTimestampUs != 0) {
          const auto timestamp_us = std::chrono::microseconds {
            static_cast<std::chrono::microseconds::rep>(info.ulTimestampUs)
          };
          const auto timestamp_duration =
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(timestamp_us);
          const auto frame_timestamp = std::chrono::steady_clock::time_point {timestamp_duration};
          if (frame_timestamp <= std::chrono::steady_clock::now()) {
            img_out->frame_timestamp = frame_timestamp;
          }
        }

        if (img->tex.copy((std::uint8_t *) device_ptr, img->height, img->row_pitch)) {
          return platf::capture_e::error;
        }

        return platf::capture_e::ok;
      }

      /**
       * @brief Create AVCodec encode device.
       *
       * @param pix_fmt Sunshine pixel format to convert or allocate for.
       * @return Constructed AVCodec encode device object.
       */
      std::unique_ptr<platf::avcodec_encode_device_t> make_avcodec_encode_device(platf::pix_fmt_e pix_fmt) override {
        return ::cuda::make_avcodec_encode_device(width, height, true);
      }

      /**
       * @brief Create the NvFBC CUDA readback device used by software x264.
       *
       * @param pix_fmt Software pixel format requested by x264.
       * @return Constructed CUDA-to-CPU conversion device.
       */
      std::unique_ptr<platf::avcodec_encode_device_t> make_avcodec_software_encode_device(platf::pix_fmt_e pix_fmt) override {
        return ::cuda::make_avcodec_software_encode_device(width, height, pix_fmt);
      }

      std::unique_ptr<platf::nvenc_encode_device_t> make_nvenc_encode_device(platf::pix_fmt_e pix_fmt) override {
        return ::cuda::make_nvenc_encode_device(width, height, pix_fmt);
      }

      /**
       * @brief Allocate an image buffer compatible with this display backend.
       *
       * @return Allocated img object, or null when unavailable.
       */
      std::shared_ptr<platf::img_t> alloc_img() override {
        auto img = std::make_shared<cuda::img_t>();

        img->data = nullptr;
        img->width = width;
        img->height = height;
        img->pixel_pitch = 4;
        img->row_pitch = img->width * img->pixel_pitch;

        auto tex_opt = tex_t::make(height, width * img->pixel_pitch);
        if (!tex_opt) {
          return nullptr;
        }

        img->tex = std::move(*tex_opt);

        return img;
      };

      /**
       * @brief Populate a fallback image when real capture data is unavailable.
       *
       * @return Capture status reported to the streaming pipeline.
       */
      int dummy_img(platf::img_t *) override {
        return 0;
      }

      std::chrono::nanoseconds delay;  ///< Delay before the timer task becomes eligible to run.

      bool cursor_visible;  ///< Whether the cursor should be included in the capture.
      handle_t handle;  ///< NvFBC capture handle owning the active capture session.

      NVFBC_CREATE_CAPTURE_SESSION_PARAMS capture_params;  ///< NvFBC capture-session parameters used for frame grabs.
    };
  }  // namespace nvfbc
}  // namespace cuda

namespace platf {
  /**
   * @brief Create an NvFBC CUDA display capture backend.
   *
   * @param hwdevice_type Hardware device type requested for capture or encode.
   * @param display_name Display name.
   * @param config Configuration values to apply.
   * @return Display backend, or nullptr when NvFBC/CUDA initialization fails.
   */
  std::shared_ptr<display_t> nvfbc_display(mem_type_e hwdevice_type, const std::string &display_name, const video::config_t &config) {
    if (hwdevice_type != mem_type_e::cuda) {
      BOOST_LOG(error) << "Could not initialize nvfbc display with the given hw device type"sv;
      return nullptr;
    }

    auto display = std::make_shared<cuda::nvfbc::display_t>();

    if (display->init(display_name, config)) {
      return nullptr;
    }

    return display;
  }

  /**
   * @brief Enumerate display names exposed by NvFBC.
   *
   * @return NvFBC display names, or an empty list when enumeration fails.
   */
  std::vector<std::string> nvfbc_display_names() {
    if (cuda::init() || cuda::nvfbc::init()) {
      return {};
    }

    std::vector<std::string> display_names;

    auto handle = cuda::nvfbc::handle_t::make();
    if (!handle) {
      return {};
    }

    auto status_params = handle->status();
    if (!status_params) {
      return {};
    }

    if (!status_params->bIsCapturePossible) {
      BOOST_LOG(error) << "NVidia driver doesn't support NvFBC screencasting"sv;
    }

    BOOST_LOG(info) << "Found ["sv << status_params->dwOutputNum << "] outputs"sv;
    BOOST_LOG(info) << "Virtual Desktop: "sv << status_params->screenSize.w << 'x' << status_params->screenSize.h;
    BOOST_LOG(info) << "XrandR: "sv << (status_params->bXRandRAvailable ? "available"sv : "unavailable"sv);

    for (auto x = 0; x < status_params->dwOutputNum; ++x) {
      auto &output = status_params->outputs[x];
      BOOST_LOG(info) << "-- Output --"sv;
      BOOST_LOG(debug) << "  ID: "sv << output.dwId;
      BOOST_LOG(debug) << "  Name: "sv << output.name;
      BOOST_LOG(info) << "  Resolution: "sv << output.trackedBox.w << 'x' << output.trackedBox.h;
      BOOST_LOG(info) << "  Offset: "sv << output.trackedBox.x << 'x' << output.trackedBox.y;
      display_names.emplace_back(output.name);
    }

    return display_names;
  }
}  // namespace platf
