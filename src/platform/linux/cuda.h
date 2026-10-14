/**
 * @file src/platform/linux/cuda.h
 * @brief Definitions for CUDA implementation.
 */
#pragma once

#if defined(SUNSHINE_BUILD_CUDA)
  // standard includes
  #include <cstddef>
  #include <cstdint>
  #include <memory>
  #include <optional>
  #include <string>
  #include <vector>

  // local includes
  #include "src/video_colorspace.h"

namespace platf {
  struct avcodec_encode_device_t;
  struct nvenc_encode_device_t;
  struct img_t;
  enum class pix_fmt_e;
}  // namespace platf

namespace cuda {

  namespace nvfbc {
    std::vector<std::string> display_names();
  }

  std::unique_ptr<platf::avcodec_encode_device_t> make_avcodec_encode_device(int width, int height, bool vram);
  /**
   * @brief Create an NvFBC CUDA-to-CPU encode device for x264.
   *
   * @param width Captured frame width.
   * @param height Captured frame height.
   * @param pix_fmt Software pixel format requested by the encoder.
   * @return CUDA readback encode device, or null on initialization failure.
   */
  std::unique_ptr<platf::avcodec_encode_device_t> make_avcodec_software_encode_device(int width, int height, platf::pix_fmt_e pix_fmt);
  std::unique_ptr<platf::nvenc_encode_device_t> make_nvenc_encode_device(int width, int height, platf::pix_fmt_e pix_fmt);
  std::unique_ptr<platf::nvenc_encode_device_t> make_nvenc_native10_encode_device(int width, int height, platf::pix_fmt_e pix_fmt);

  /**
   * @brief Create a GL->CUDA encoding device for consuming captured dmabufs.
   * @param in_width Width of captured frames.
   * @param in_height Height of captured frames.
   * @param offset_x Offset of content in captured frame.
   * @param offset_y Offset of content in captured frame.
   * @return FFmpeg encoding device context.
   */
  std::unique_ptr<platf::avcodec_encode_device_t> make_avcodec_gl_encode_device(int width, int height, int offset_x, int offset_y);

  int init();

  #if defined(SUNSHINE_TESTS)
  bool test_identity_gbr_8bit_conversion();
  bool test_identity_gbr_10bit_conversion();
  #endif
}  // namespace cuda

typedef struct cudaArray *cudaArray_t;

  #if !defined(__CUDACC__)
typedef struct CUstream_st *cudaStream_t;
typedef unsigned long long cudaTextureObject_t;
  #else /* defined(__CUDACC__) */
typedef __location__(device_builtin) struct CUstream_st *cudaStream_t;
typedef __location__(device_builtin) unsigned long long cudaTextureObject_t;
  #endif /* !defined(__CUDACC__) */

namespace cuda {

  class freeCudaPtr_t {
  public:
    void operator()(void *ptr);
  };

  class freeCudaStream_t {
  public:
    void operator()(cudaStream_t ptr);
  };

  using ptr_t = std::unique_ptr<void, freeCudaPtr_t>;
  using stream_t = std::unique_ptr<CUstream_st, freeCudaStream_t>;

  stream_t make_stream(int flags = 0);

  int scale_xrgb10_to_yuv444_10bit(std::uintptr_t source,
                                   std::uint32_t source_pitch,
                                   int source_width,
                                   int source_height,
                                   std::uint8_t *Y,
                                   std::uint8_t *U,
                                   std::uint8_t *V,
                                   std::uint32_t destination_pitch,
                                   int destination_width,
                                   int destination_height,
                                   stream_t::pointer stream);

  struct viewport_t {
    int width;
    int height;
    int offsetX;
    int offsetY;
  };

  class tex_t {
  public:
    static std::optional<tex_t> make(int height, int pitch);

    tex_t();
    tex_t(tex_t &&);

    tex_t &operator=(tex_t &&other);

    ~tex_t();

    int copy(std::uint8_t *src, int height, int pitch);

    cudaArray_t array;

    struct texture {
      cudaTextureObject_t point;
      cudaTextureObject_t linear;
    } texture;
  };

  class sws_t {
  public:
    sws_t() = default;
    sws_t(int in_width, int in_height, int out_width, int out_height, int pitch, int threadsPerBlock, ptr_t &&color_matrix);

    /**
     * in_width, in_height -- The width and height of the captured image in pixels
     * out_width, out_height -- the width and height of the NV12 image in pixels
     *
     * pitch -- The size of a single row of pixels in bytes
     */
    static std::optional<sws_t> make(int in_width, int in_height, int out_width, int out_height, int pitch);

    // Converts loaded image into a CUDevicePtr
    int convert_nv12(std::uint8_t *Y, std::uint8_t *UV, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream);
    int convert_nv12(std::uint8_t *Y, std::uint8_t *UV, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream, const viewport_t &viewport);
    int convert_p010(std::uint8_t *Y, std::uint8_t *UV, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream);
    int convert_p010(std::uint8_t *Y, std::uint8_t *UV, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream, const viewport_t &viewport);
    int convert_yuv422(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream);
    int convert_yuv422(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream, const viewport_t &viewport);
    int convert_yuv422_10bit(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream);
    int convert_yuv422_10bit(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream, const viewport_t &viewport);
    int convert_yuv444(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitch, cudaTextureObject_t texture, stream_t::pointer stream);
    int convert_yuv444(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitch, cudaTextureObject_t texture, stream_t::pointer stream, const viewport_t &viewport);
    int convert_yuv444_10bit(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitch, cudaTextureObject_t texture, stream_t::pointer stream);
    int convert_yuv444_10bit(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitch, cudaTextureObject_t texture, stream_t::pointer stream, const viewport_t &viewport);

    void apply_colorspace(const video::sunshine_colorspace_t &colorspace);

    int load_ram(platf::img_t &img, cudaArray_t array);

    ptr_t color_matrix;

    int threadsPerBlock;

    viewport_t viewport;

    float scale;
  };

  /**
   * @brief Area-average an NvFBC texture entirely on the GPU before conversion.
   *
   * Two separable passes bound work to the source dimensions, including very
   * small destinations. Float intermediates retain fractional 8-bit samples
   * until the final 8/10-bit conversion. Allocate once per encoder, not per frame.
   */
  class area_scaler_t {
  public:
    /**
     * @brief Allocate a downscaler; return null on invalid sizes or CUDA failure.
     * @param source_width Captured width in pixels.
     * @param source_height Captured height in pixels.
     * @param width Content viewport width, excluding letterbox bars.
     * @param height Content viewport height, excluding letterbox bars.
     */
    static std::unique_ptr<area_scaler_t> make(int source_width, int source_height, int width, int height);

    /** @brief Destroy the texture before releasing its backing device storage. */
    ~area_scaler_t();

    /**
     * @brief Submit both passes on the caller's conversion stream.
     * @param source Point-sampled, normalized BGRA capture texture.
     * @param stream Stream shared with conversion and NVENC submission.
     * @return Zero on success, negative on a CUDA launch failure.
     */
    int resize(cudaTextureObject_t source, stream_t::pointer stream);

    /** @brief Return the point-sampled float texture for scale-1 conversion. */
    cudaTextureObject_t texture() const { return texture_; }

  private:
    area_scaler_t() = default;
    ptr_t horizontal_;  ///< Float BGRA intermediate; destination width, source height.
    ptr_t scaled_;  ///< Float BGRA result; destination width and height.
    std::size_t horizontal_pitch_ = 0;  ///< Intermediate row stride in bytes.
    std::size_t scaled_pitch_ = 0;  ///< Result row stride in bytes.
    cudaTextureObject_t texture_ = 0;  ///< Point texture backed by scaled_.
    int source_width_ = 0;  ///< Captured width.
    int source_height_ = 0;  ///< Captured height.
    int width_ = 0;  ///< Resampled width.
    int height_ = 0;  ///< Resampled height.
  };
}  // namespace cuda

#endif
