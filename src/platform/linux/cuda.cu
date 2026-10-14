/**
 * @file src/platform/linux/cuda.cu
 * @brief CUDA implementation for Linux.
 */
// standard includes
#include <algorithm>
#include <chrono>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>

// platform includes
#include <helper_math.h>

// local includes
#include "cuda.h"

using namespace std::literals;

#define SUNSHINE_STRINGVIEW_HELPER(x) x##sv
#define SUNSHINE_STRINGVIEW(x) SUNSHINE_STRINGVIEW_HELPER(x)

#define CU_CHECK(x, y) \
  if (check((x), SUNSHINE_STRINGVIEW(y ": "))) \
  return -1

#define CU_CHECK_VOID(x, y) \
  if (check((x), SUNSHINE_STRINGVIEW(y ": "))) \
    return;

#define CU_CHECK_PTR(x, y) \
  if (check((x), SUNSHINE_STRINGVIEW(y ": "))) \
    return nullptr;

#define CU_CHECK_OPT(x, y) \
  if (check((x), SUNSHINE_STRINGVIEW(y ": "))) \
    return std::nullopt;

#define CU_CHECK_IGNORE(x, y) \
  check((x), SUNSHINE_STRINGVIEW(y ": "))

using namespace std::literals;

// Special declarations
/**
 * NVCC tends to have problems with standard headers.
 * Don't include common.h, instead use bare minimum
 * of standard headers and duplicate declarations of necessary classes.
 * Not pretty and extremely error-prone, fix at earliest convenience.
 */
namespace platf {
  struct img_t: std::enable_shared_from_this<img_t> {
  public:
    std::uint8_t *data {};
    std::int32_t width {};
    std::int32_t height {};
    std::int32_t pixel_pitch {};
    std::int32_t row_pitch {};

    std::optional<std::chrono::steady_clock::time_point> frame_timestamp;

    virtual ~img_t() = default;
  };
}  // namespace platf

// End special declarations

namespace cuda {

  struct alignas(16) cuda_color_t {
    float4 color_vec_y;
    float4 color_vec_u;
    float4 color_vec_v;
    float2 range_y;
    float2 range_uv;
  };

  static_assert(sizeof(video::color_t) == sizeof(cuda::cuda_color_t), "color matrix struct mismatch");

  auto constexpr INVALID_TEXTURE = std::numeric_limits<cudaTextureObject_t>::max();

  template<class T>
  inline T div_align(T l, T r) {
    return (l + r - 1) / r;
  }

  void pass_error(const std::string_view &sv, const char *name, const char *description);

  inline static int check(cudaError_t result, const std::string_view &sv) {
    if (result) {
      auto name = cudaGetErrorName(result);
      auto description = cudaGetErrorString(result);

      pass_error(sv, name, description);
      return -1;
    }

    return 0;
  }

  template<class T>
  ptr_t make_ptr() {
    void *p;
    CU_CHECK_PTR(cudaMalloc(&p, sizeof(T)), "Couldn't allocate color matrix");

    ptr_t ptr {p};

    return ptr;
  }

  void freeCudaPtr_t::operator()(void *ptr) {
    CU_CHECK_IGNORE(cudaFree(ptr), "Couldn't free cuda device pointer");
  }

  void freeCudaStream_t::operator()(cudaStream_t ptr) {
    CU_CHECK_IGNORE(cudaStreamDestroy(ptr), "Couldn't free cuda stream");
  }

  stream_t make_stream(int flags) {
    cudaStream_t stream;

    if (!flags) {
      CU_CHECK_PTR(cudaStreamCreate(&stream), "Couldn't create cuda stream");
    } else {
      CU_CHECK_PTR(cudaStreamCreateWithFlags(&stream, flags), "Couldn't create cuda stream with flags");
    }

    return stream_t {stream};
  }

  inline __device__ float3 bgra_to_rgb(uchar4 vec) {
    return make_float3((float) vec.z, (float) vec.y, (float) vec.x);
  }

  inline __device__ float3 bgra_to_rgb(float4 vec) {
    return make_float3(vec.z, vec.y, vec.x);
  }

  inline __device__ float2 calcUV(float3 pixel, const cuda_color_t *const color_matrix) {
    float4 vec_u = color_matrix->color_vec_u;
    float4 vec_v = color_matrix->color_vec_v;

    float u = dot(pixel, make_float3(vec_u)) + vec_u.w;
    float v = dot(pixel, make_float3(vec_v)) + vec_v.w;

    u = u * color_matrix->range_uv.x + color_matrix->range_uv.y;
    v = v * color_matrix->range_uv.x + color_matrix->range_uv.y;

    return make_float2(u, v);
  }

  inline __device__ float calcY(float3 pixel, const cuda_color_t *const color_matrix) {
    float4 vec_y = color_matrix->color_vec_y;

    return (dot(pixel, make_float3(vec_y)) + vec_y.w) * color_matrix->range_y.x + color_matrix->range_y.y;
  }

  inline __device__ float calcU(float3 pixel, const cuda_color_t *const color_matrix) {
    float4 vec_u = color_matrix->color_vec_u;

    return (dot(pixel, make_float3(vec_u)) + vec_u.w) * color_matrix->range_uv.x + color_matrix->range_uv.y;
  }

  inline __device__ float calcV(float3 pixel, const cuda_color_t *const color_matrix) {
    float4 vec_v = color_matrix->color_vec_v;

    return (dot(pixel, make_float3(vec_v)) + vec_v.w) * color_matrix->range_uv.x + color_matrix->range_uv.y;
  }

  __global__ void RGBA_to_NV12(
    cudaTextureObject_t srcImage,
    std::uint8_t *dstY,
    std::uint8_t *dstUV,
    std::uint32_t dstPitchY,
    std::uint32_t dstPitchUV,
    float scale,
    const viewport_t viewport,
    const cuda_color_t *const color_matrix
  ) {
    int idX = (threadIdx.x + blockDim.x * blockIdx.x) * 2;
    int idY = (threadIdx.y + blockDim.y * blockIdx.y) * 2;

    if (idX >= viewport.width) {
      return;
    }
    if (idY >= viewport.height) {
      return;
    }

    float x = idX * scale;
    float y = idY * scale;

    idX += viewport.offsetX;
    idY += viewport.offsetY;

    uint8_t *dstY0 = dstY + idX + idY * dstPitchY;
    uint8_t *dstY1 = dstY + idX + (idY + 1) * dstPitchY;
    dstUV = dstUV + idX + (idY / 2 * dstPitchUV);

    float3 rgb_lt = bgra_to_rgb(tex2D<float4>(srcImage, x, y));
    float3 rgb_rt = bgra_to_rgb(tex2D<float4>(srcImage, x + scale, y));
    float3 rgb_lb = bgra_to_rgb(tex2D<float4>(srcImage, x, y + scale));
    float3 rgb_rb = bgra_to_rgb(tex2D<float4>(srcImage, x + scale, y + scale));

    float2 uv_lt = calcUV(rgb_lt, color_matrix) * 256.0f;
    float2 uv_rt = calcUV(rgb_rt, color_matrix) * 256.0f;
    float2 uv_lb = calcUV(rgb_lb, color_matrix) * 256.0f;
    float2 uv_rb = calcUV(rgb_rb, color_matrix) * 256.0f;

    float2 uv = (uv_lt + uv_lb + uv_rt + uv_rb) * 0.25f;

    dstUV[0] = uv.x;
    dstUV[1] = uv.y;
    dstY0[0] = calcY(rgb_lt, color_matrix) * 245.0f;  // 245.0f is a magic number to ensure slight changes in luminosity are more visible
    dstY0[1] = calcY(rgb_rt, color_matrix) * 245.0f;  // 245.0f is a magic number to ensure slight changes in luminosity are more visible
    dstY1[0] = calcY(rgb_lb, color_matrix) * 245.0f;  // 245.0f is a magic number to ensure slight changes in luminosity are more visible
    dstY1[1] = calcY(rgb_rb, color_matrix) * 245.0f;  // 245.0f is a magic number to ensure slight changes in luminosity are more visible
  }

  __global__ void RGBA_to_YUV444(
    cudaTextureObject_t srcImage,
    std::uint8_t *dstY,
    std::uint8_t *dstU,
    std::uint8_t *dstV,
    std::uint32_t dstPitchY,
    float scale,
    const viewport_t viewport,
    const cuda_color_t *const color_matrix
  ) {
    int idX = threadIdx.x + blockDim.x * blockIdx.x;
    int idY = threadIdx.y + blockDim.y * blockIdx.y;

    if (idX >= viewport.width) {
      return;
    }
    if (idY >= viewport.height) {
      return;
    }

    float x = idX * scale;
    float y = idY * scale;

    idX += viewport.offsetX;
    idY += viewport.offsetY;

    dstY = dstY + idX + idY * dstPitchY;
    dstU = dstU + idX + idY * dstPitchY;
    dstV = dstV + idX + idY * dstPitchY;

    float3 rgb = bgra_to_rgb(tex2D<float4>(srcImage, x, y));

    dstY[0] = calcY(rgb, color_matrix) * 255.0f;
    dstU[0] = calcU(rgb, color_matrix) * 255.0f;
    dstV[0] = calcV(rgb, color_matrix) * 255.0f;
  }

  inline __device__ std::uint16_t to_msb_aligned_10bit(float component) {
    component = fminf(fmaxf(component, 0.0f), 1.0f);
    return static_cast<std::uint16_t>(__float2uint_rn(component * 1023.0f) << 6);
  }

  inline __device__ std::uint8_t to_8bit(float component) {
    component = fminf(fmaxf(component, 0.0f), 1.0f);
    return static_cast<std::uint8_t>(__float2uint_rn(component * 255.0f));
  }

  inline __device__ std::uint16_t to_lsb_aligned_10bit(float component) {
    component = fminf(fmaxf(component, 0.0f), 1.0f);
    return static_cast<std::uint16_t>(__float2uint_rn(component * 1023.0f));
  }

  __global__ void RGBA_to_YUV422(
    cudaTextureObject_t srcImage,
    std::uint8_t *dstY,
    std::uint8_t *dstU,
    std::uint8_t *dstV,
    std::uint32_t dstPitchY,
    std::uint32_t dstPitchUV,
    float scale,
    const viewport_t viewport,
    const cuda_color_t *const color_matrix
  ) {
    int idX = (threadIdx.x + blockDim.x * blockIdx.x) * 2;
    int idY = threadIdx.y + blockDim.y * blockIdx.y;
    if (idX >= viewport.width || idY >= viewport.height) {
      return;
    }

    const float x = idX * scale;
    const float y = idY * scale;
    idX += viewport.offsetX;
    idY += viewport.offsetY;

    const float3 rgb_left = bgra_to_rgb(tex2D<float4>(srcImage, x, y));
    const float3 rgb_right = bgra_to_rgb(tex2D<float4>(srcImage, x + scale, y));
    const float2 uv = (calcUV(rgb_left, color_matrix) + calcUV(rgb_right, color_matrix)) * 0.5f;
    auto *y_out = dstY + idY * dstPitchY + idX;
    y_out[0] = to_8bit(calcY(rgb_left, color_matrix));
    y_out[1] = to_8bit(calcY(rgb_right, color_matrix));
    dstU[idY * dstPitchUV + idX / 2] = to_8bit(uv.x);
    dstV[idY * dstPitchUV + idX / 2] = to_8bit(uv.y);
  }

  __global__ void RGBA_to_YUV422_10bit(
    cudaTextureObject_t srcImage,
    std::uint8_t *dstYBytes,
    std::uint8_t *dstUBytes,
    std::uint8_t *dstVBytes,
    std::uint32_t dstPitchY,
    std::uint32_t dstPitchUV,
    float scale,
    const viewport_t viewport,
    const cuda_color_t *const color_matrix
  ) {
    int idX = (threadIdx.x + blockDim.x * blockIdx.x) * 2;
    int idY = threadIdx.y + blockDim.y * blockIdx.y;
    if (idX >= viewport.width || idY >= viewport.height) {
      return;
    }

    const float x = idX * scale;
    const float y = idY * scale;
    idX += viewport.offsetX;
    idY += viewport.offsetY;

    const float3 rgb_left = bgra_to_rgb(tex2D<float4>(srcImage, x, y));
    const float3 rgb_right = bgra_to_rgb(tex2D<float4>(srcImage, x + scale, y));
    const float2 uv = (calcUV(rgb_left, color_matrix) + calcUV(rgb_right, color_matrix)) * 0.5f;
    auto *y_out = reinterpret_cast<std::uint16_t *>(dstYBytes + idY * dstPitchY) + idX;
    auto *u_out = reinterpret_cast<std::uint16_t *>(dstUBytes + idY * dstPitchUV) + idX / 2;
    auto *v_out = reinterpret_cast<std::uint16_t *>(dstVBytes + idY * dstPitchUV) + idX / 2;
    y_out[0] = to_lsb_aligned_10bit(calcY(rgb_left, color_matrix));
    y_out[1] = to_lsb_aligned_10bit(calcY(rgb_right, color_matrix));
    u_out[0] = to_lsb_aligned_10bit(uv.x);
    v_out[0] = to_lsb_aligned_10bit(uv.y);
  }

  __global__ void RGBA_to_P010(
    cudaTextureObject_t srcImage,
    std::uint8_t *dstYBytes,
    std::uint8_t *dstUVBytes,
    std::uint32_t dstPitchY,
    std::uint32_t dstPitchUV,
    float scale,
    const viewport_t viewport,
    const cuda_color_t *const color_matrix
  ) {
    int idX = (threadIdx.x + blockDim.x * blockIdx.x) * 2;
    int idY = (threadIdx.y + blockDim.y * blockIdx.y) * 2;

    if (idX >= viewport.width || idY >= viewport.height) {
      return;
    }

    const float x = idX * scale;
    const float y = idY * scale;
    idX += viewport.offsetX;
    idY += viewport.offsetY;

    auto *dstY0 = reinterpret_cast<std::uint16_t *>(dstYBytes + idY * dstPitchY) + idX;
    auto *dstY1 = reinterpret_cast<std::uint16_t *>(dstYBytes + (idY + 1) * dstPitchY) + idX;
    auto *dstUV = reinterpret_cast<std::uint16_t *>(dstUVBytes + (idY / 2) * dstPitchUV) + idX;

    const float3 rgb_lt = bgra_to_rgb(tex2D<float4>(srcImage, x, y));
    const float3 rgb_rt = bgra_to_rgb(tex2D<float4>(srcImage, x + scale, y));
    const float3 rgb_lb = bgra_to_rgb(tex2D<float4>(srcImage, x, y + scale));
    const float3 rgb_rb = bgra_to_rgb(tex2D<float4>(srcImage, x + scale, y + scale));
    const float2 uv = (calcUV(rgb_lt, color_matrix) + calcUV(rgb_rt, color_matrix) +
                       calcUV(rgb_lb, color_matrix) + calcUV(rgb_rb, color_matrix)) * 0.25f;

    dstY0[0] = to_msb_aligned_10bit(calcY(rgb_lt, color_matrix));
    dstY0[1] = to_msb_aligned_10bit(calcY(rgb_rt, color_matrix));
    dstY1[0] = to_msb_aligned_10bit(calcY(rgb_lb, color_matrix));
    dstY1[1] = to_msb_aligned_10bit(calcY(rgb_rb, color_matrix));
    dstUV[0] = to_msb_aligned_10bit(uv.x);
    dstUV[1] = to_msb_aligned_10bit(uv.y);
  }

  __global__ void RGBA_to_YUV444_10bit(
    cudaTextureObject_t srcImage,
    std::uint8_t *dstYBytes,
    std::uint8_t *dstUBytes,
    std::uint8_t *dstVBytes,
    std::uint32_t dstPitch,
    float scale,
    const viewport_t viewport,
    const cuda_color_t *const color_matrix
  ) {
    int idX = threadIdx.x + blockDim.x * blockIdx.x;
    int idY = threadIdx.y + blockDim.y * blockIdx.y;

    if (idX >= viewport.width || idY >= viewport.height) {
      return;
    }

    const float x = idX * scale;
    const float y = idY * scale;

    idX += viewport.offsetX;
    idY += viewport.offsetY;

    auto *dstY = reinterpret_cast<std::uint16_t *>(dstYBytes + idY * dstPitch) + idX;
    auto *dstU = reinterpret_cast<std::uint16_t *>(dstUBytes + idY * dstPitch) + idX;
    auto *dstV = reinterpret_cast<std::uint16_t *>(dstVBytes + idY * dstPitch) + idX;

    const float3 rgb = bgra_to_rgb(tex2D<float4>(srcImage, x, y));
    dstY[0] = to_msb_aligned_10bit(calcY(rgb, color_matrix));
    dstU[0] = to_msb_aligned_10bit(calcU(rgb, color_matrix));
    dstV[0] = to_msb_aligned_10bit(calcV(rgb, color_matrix));
  }

  __device__ __forceinline__ std::uint32_t bilinear_xrgb10_channel(
    std::uint32_t top_left,
    std::uint32_t top_right,
    std::uint32_t bottom_left,
    std::uint32_t bottom_right,
    std::uint32_t shift,
    float x_weight,
    float y_weight
  ) {
    const float top = static_cast<float>((top_left >> shift) & 0x3ffU) +
      (static_cast<float>((top_right >> shift) & 0x3ffU) -
       static_cast<float>((top_left >> shift) & 0x3ffU)) * x_weight;
    const float bottom = static_cast<float>((bottom_left >> shift) & 0x3ffU) +
      (static_cast<float>((bottom_right >> shift) & 0x3ffU) -
       static_cast<float>((bottom_left >> shift) & 0x3ffU)) * x_weight;
    return __float2uint_rn(top + (bottom - top) * y_weight);
  }

  __global__ void XRGB10_to_identity_YUV444_10bit(
    const std::uint8_t *source,
    std::uint32_t source_pitch,
    int source_width,
    int source_height,
    std::uint8_t *dstYBytes,
    std::uint8_t *dstUBytes,
    std::uint8_t *dstVBytes,
    std::uint32_t destination_pitch,
    int destination_width,
    int destination_height
  ) {
    const int x = threadIdx.x + blockDim.x * blockIdx.x;
    const int y = threadIdx.y + blockDim.y * blockIdx.y;
    if (x >= destination_width || y >= destination_height) {
      return;
    }

    std::uint32_t red_value;
    std::uint32_t green_value;
    std::uint32_t blue_value;
    if (source_width == destination_width && source_height == destination_height) {
      const auto pixel = reinterpret_cast<const std::uint32_t *>(
        source + static_cast<std::size_t>(y) * source_pitch)[x];
      red_value = pixel & 0x3ffU;
      green_value = (pixel >> 10U) & 0x3ffU;
      blue_value = (pixel >> 20U) & 0x3ffU;
    } else {
      // Center-aligned bilinear sampling keeps Scaled-Span on the GPU while
      // preserving the packed depth-30 X11 source and identity-GBR output.
      const float source_x = fmaxf(
        0.0f,
        (static_cast<float>(x) + 0.5f) * source_width / destination_width - 0.5f);
      const float source_y = fmaxf(
        0.0f,
        (static_cast<float>(y) + 0.5f) * source_height / destination_height - 0.5f);
      const int x0 = min(static_cast<int>(source_x), source_width - 1);
      const int y0 = min(static_cast<int>(source_y), source_height - 1);
      const int x1 = min(x0 + 1, source_width - 1);
      const int y1 = min(y0 + 1, source_height - 1);
      const float x_weight = source_x - x0;
      const float y_weight = source_y - y0;
      const auto *top = reinterpret_cast<const std::uint32_t *>(
        source + static_cast<std::size_t>(y0) * source_pitch);
      const auto *bottom = reinterpret_cast<const std::uint32_t *>(
        source + static_cast<std::size_t>(y1) * source_pitch);
      red_value = bilinear_xrgb10_channel(
        top[x0], top[x1], bottom[x0], bottom[x1], 0U,
        x_weight, y_weight);
      green_value = bilinear_xrgb10_channel(
        top[x0], top[x1], bottom[x0], bottom[x1], 10U,
        x_weight, y_weight);
      blue_value = bilinear_xrgb10_channel(
        top[x0], top[x1], bottom[x0], bottom[x1], 20U,
        x_weight, y_weight);
    }

    auto *green_plane = reinterpret_cast<std::uint16_t *>(
      dstYBytes + static_cast<std::size_t>(y) * destination_pitch);
    auto *blue_plane = reinterpret_cast<std::uint16_t *>(
      dstUBytes + static_cast<std::size_t>(y) * destination_pitch);
    auto *red_plane = reinterpret_cast<std::uint16_t *>(
      dstVBytes + static_cast<std::size_t>(y) * destination_pitch);
    red_plane[x] = static_cast<std::uint16_t>(red_value << 6U);
    green_plane[x] = static_cast<std::uint16_t>(green_value << 6U);
    blue_plane[x] = static_cast<std::uint16_t>(blue_value << 6U);
  }

  int tex_t::copy(std::uint8_t *src, int height, int pitch) {
    CU_CHECK(cudaMemcpy2DToArray(array, 0, 0, src, pitch, pitch, height, cudaMemcpyDeviceToDevice), "Couldn't copy to cuda array from deviceptr");

    return 0;
  }

  /**
   * @brief Integrate each output column's exact source-pixel footprint.
   * @param source Point-sampled normalized BGRA capture texture.
   * @param output Float intermediate storage.
   * @param pitch Intermediate byte stride.
   * @param source_width Captured width.
   * @param source_height Captured height.
   * @param width Destination width.
   */
  __global__ void area_reduce_horizontal(cudaTextureObject_t source, std::uint8_t *output,
                                        std::size_t pitch, int source_width, int source_height, int width) {
    const int x = threadIdx.x + blockDim.x * blockIdx.x;
    const int y = threadIdx.y + blockDim.y * blockIdx.y;
    if (x >= width || y >= source_height) {
      return;
    }
    const float begin = static_cast<float>(x) * source_width / width;
    const float end = static_cast<float>(x + 1) * source_width / width;
    float4 total = make_float4(0.0f);
    const int last = min(static_cast<int>(ceilf(end)), source_width);
    for (int column = static_cast<int>(floorf(begin)); column < last; ++column) {
      const float weight = fminf(end, column + 1.0f) - fmaxf(begin, static_cast<float>(column));
      total += tex2D<float4>(source, column + 0.5f, y + 0.5f) * weight;
    }
    reinterpret_cast<float4 *>(output + y * pitch)[x] = total / (end - begin);
  }

  /**
   * @brief Integrate rows without quantizing the horizontal result to 8 bits.
   * @param source Float horizontal intermediate.
   * @param source_pitch Intermediate byte stride.
   * @param output Float result storage.
   * @param pitch Result byte stride.
   * @param source_height Captured height.
   * @param width Destination width.
   * @param height Destination height.
   */
  __global__ void area_reduce_vertical(const std::uint8_t *source, std::size_t source_pitch,
                                      std::uint8_t *output, std::size_t pitch,
                                      int source_height, int width, int height) {
    const int x = threadIdx.x + blockDim.x * blockIdx.x;
    const int y = threadIdx.y + blockDim.y * blockIdx.y;
    if (x >= width || y >= height) {
      return;
    }
    const float begin = static_cast<float>(y) * source_height / height;
    const float end = static_cast<float>(y + 1) * source_height / height;
    float4 total = make_float4(0.0f);
    const int last = min(static_cast<int>(ceilf(end)), source_height);
    for (int row = static_cast<int>(floorf(begin)); row < last; ++row) {
      const float weight = fminf(end, row + 1.0f) - fmaxf(begin, static_cast<float>(row));
      total += reinterpret_cast<const float4 *>(source + row * source_pitch)[x] * weight;
    }
    reinterpret_cast<float4 *>(output + y * pitch)[x] = total / (end - begin);
  }

  std::unique_ptr<area_scaler_t> area_scaler_t::make(int source_width, int source_height, int width, int height) {
    if (source_width <= 0 || source_height <= 0 || width <= 0 || height <= 0 ||
        width > source_width || height > source_height) {
      return nullptr;
    }
    auto scaler = std::unique_ptr<area_scaler_t>(new area_scaler_t());
    scaler->source_width_ = source_width;
    scaler->source_height_ = source_height;
    scaler->width_ = width;
    scaler->height_ = height;
    void *buffer = nullptr;
    const auto row_bytes = static_cast<std::size_t>(width) * sizeof(float4);
    CU_CHECK_PTR(cudaMallocPitch(&buffer, &scaler->horizontal_pitch_, row_bytes, source_height),
                 "Couldn't allocate horizontal area-reduction surface");
    scaler->horizontal_.reset(buffer);
    CU_CHECK_PTR(cudaMallocPitch(&buffer, &scaler->scaled_pitch_, row_bytes, height),
                 "Couldn't allocate area-reduction result");
    scaler->scaled_.reset(buffer);
    cudaResourceDesc resource {};
    resource.resType = cudaResourceTypePitch2D;
    resource.res.pitch2D.devPtr = scaler->scaled_.get();
    resource.res.pitch2D.desc = cudaCreateChannelDesc<float4>();
    resource.res.pitch2D.width = width;
    resource.res.pitch2D.height = height;
    resource.res.pitch2D.pitchInBytes = scaler->scaled_pitch_;
    cudaTextureDesc desc {};
    desc.readMode = cudaReadModeElementType;
    desc.filterMode = cudaFilterModePoint;
    desc.addressMode[0] = desc.addressMode[1] = cudaAddressModeClamp;
    CU_CHECK_PTR(cudaCreateTextureObject(&scaler->texture_, &resource, &desc, nullptr),
                 "Couldn't create area-reduction texture");
    return scaler;
  }

  area_scaler_t::~area_scaler_t() {
    if (texture_) {
      CU_CHECK_IGNORE(cudaDestroyTextureObject(texture_), "Couldn't free area-reduction texture");
    }
  }

  int area_scaler_t::resize(cudaTextureObject_t source, stream_t::pointer stream) {
    const dim3 block(32, 8);
    area_reduce_horizontal<<<dim3(div_align(width_, 32), div_align(source_height_, 8)), block, 0, stream>>>(
      source, static_cast<std::uint8_t *>(horizontal_.get()), horizontal_pitch_, source_width_, source_height_, width_);
    CU_CHECK(cudaGetLastError(), "Horizontal area reduction failed");
    area_reduce_vertical<<<dim3(div_align(width_, 32), div_align(height_, 8)), block, 0, stream>>>(
      static_cast<const std::uint8_t *>(horizontal_.get()), horizontal_pitch_,
      static_cast<std::uint8_t *>(scaled_.get()), scaled_pitch_, source_height_, width_, height_);
    return CU_CHECK_IGNORE(cudaGetLastError(), "Vertical area reduction failed");
  }

  std::optional<tex_t> tex_t::make(int height, int pitch) {
    tex_t tex;

    auto format = cudaCreateChannelDesc<uchar4>();
    CU_CHECK_OPT(cudaMallocArray(&tex.array, &format, pitch, height, cudaArrayDefault), "Couldn't allocate cuda array");

    cudaResourceDesc res {};
    res.resType = cudaResourceTypeArray;
    res.res.array.array = tex.array;

    cudaTextureDesc desc {};

    desc.readMode = cudaReadModeNormalizedFloat;
    desc.filterMode = cudaFilterModePoint;
    desc.normalizedCoords = false;

    std::fill_n(std::begin(desc.addressMode), 2, cudaAddressModeClamp);

    CU_CHECK_OPT(cudaCreateTextureObject(&tex.texture.point, &res, &desc, nullptr), "Couldn't create cuda texture that uses point interpolation");

    desc.filterMode = cudaFilterModeLinear;

    CU_CHECK_OPT(cudaCreateTextureObject(&tex.texture.linear, &res, &desc, nullptr), "Couldn't create cuda texture that uses linear interpolation");

    return tex;
  }

  tex_t::tex_t():
      array {},
      texture {INVALID_TEXTURE, INVALID_TEXTURE} {
  }

  tex_t::tex_t(tex_t &&other):
      array {other.array},
      texture {other.texture} {
    other.array = 0;
    other.texture.point = INVALID_TEXTURE;
    other.texture.linear = INVALID_TEXTURE;
  }

  tex_t &tex_t::operator=(tex_t &&other) {
    std::swap(array, other.array);
    std::swap(texture, other.texture);

    return *this;
  }

  tex_t::~tex_t() {
    if (texture.point != INVALID_TEXTURE) {
      CU_CHECK_IGNORE(cudaDestroyTextureObject(texture.point), "Couldn't deallocate cuda texture that uses point interpolation");

      texture.point = INVALID_TEXTURE;
    }

    if (texture.linear != INVALID_TEXTURE) {
      CU_CHECK_IGNORE(cudaDestroyTextureObject(texture.linear), "Couldn't deallocate cuda texture that uses linear interpolation");

      texture.linear = INVALID_TEXTURE;
    }

    if (array) {
      CU_CHECK_IGNORE(cudaFreeArray(array), "Couldn't deallocate cuda array");

      array = cudaArray_t {};
    }
  }

  sws_t::sws_t(int in_width, int in_height, int out_width, int out_height, int pitch, int threadsPerBlock, ptr_t &&color_matrix):
      threadsPerBlock {threadsPerBlock},
      color_matrix {std::move(color_matrix)} {
    // Ensure aspect ratio is maintained
    auto scalar = std::fminf(out_width / (float) in_width, out_height / (float) in_height);
    auto out_width_f = in_width * scalar;
    auto out_height_f = in_height * scalar;

    // result is always positive
    auto offsetX_f = (out_width - out_width_f) / 2;
    auto offsetY_f = (out_height - out_height_f) / 2;

    viewport.width = out_width_f;
    viewport.height = out_height_f;

    viewport.offsetX = offsetX_f;
    viewport.offsetY = offsetY_f;

    scale = 1.0f / scalar;
  }

  std::optional<sws_t> sws_t::make(int in_width, int in_height, int out_width, int out_height, int pitch) {
    cudaDeviceProp props;
    int device;
    CU_CHECK_OPT(cudaGetDevice(&device), "Couldn't get cuda device");
    CU_CHECK_OPT(cudaGetDeviceProperties(&props, device), "Couldn't get cuda device properties");

    auto ptr = make_ptr<cuda_color_t>();
    if (!ptr) {
      return std::nullopt;
    }

    return std::make_optional<sws_t>(in_width, in_height, out_width, out_height, pitch, props.maxThreadsPerMultiProcessor / props.maxBlocksPerMultiProcessor, std::move(ptr));
  }

  int sws_t::convert_nv12(std::uint8_t *Y, std::uint8_t *UV, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream) {
    return convert_nv12(Y, UV, pitchY, pitchUV, texture, stream, viewport);
  }

  int sws_t::convert_nv12(std::uint8_t *Y, std::uint8_t *UV, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream, const viewport_t &viewport) {
    int threadsX = viewport.width / 2;
    int threadsY = viewport.height / 2;

    dim3 block(threadsPerBlock);
    dim3 grid(div_align(threadsX, threadsPerBlock), threadsY);

    RGBA_to_NV12<<<grid, block, 0, stream>>>(texture, Y, UV, pitchY, pitchUV, scale, viewport, (cuda_color_t *) color_matrix.get());

    return CU_CHECK_IGNORE(cudaGetLastError(), "RGBA_to_NV12 failed");
  }

  int sws_t::convert_p010(std::uint8_t *Y, std::uint8_t *UV, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream) {
    return convert_p010(Y, UV, pitchY, pitchUV, texture, stream, viewport);
  }

  int sws_t::convert_p010(std::uint8_t *Y, std::uint8_t *UV, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream, const viewport_t &viewport) {
    const int threadsX = viewport.width / 2;
    const int threadsY = viewport.height / 2;

    dim3 block(threadsPerBlock);
    dim3 grid(div_align(threadsX, threadsPerBlock), threadsY);

    RGBA_to_P010<<<grid, block, 0, stream>>>(texture, Y, UV, pitchY, pitchUV, scale, viewport, (cuda_color_t *) color_matrix.get());

    return CU_CHECK_IGNORE(cudaGetLastError(), "RGBA_to_P010 failed");
  }

  int sws_t::convert_yuv444(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitch, cudaTextureObject_t texture, stream_t::pointer stream) {
    return convert_yuv444(Y, U, V, pitch, texture, stream, viewport);
  }

  int sws_t::convert_yuv422(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream) {
    return convert_yuv422(Y, U, V, pitchY, pitchUV, texture, stream, viewport);
  }

  int sws_t::convert_yuv422(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream, const viewport_t &requested_viewport) {
    auto aligned_viewport = requested_viewport;
    aligned_viewport.offsetX &= ~1;
    aligned_viewport.width &= ~1;
    const int threadsX = aligned_viewport.width / 2;
    const int threadsY = aligned_viewport.height;
    dim3 block(threadsPerBlock);
    dim3 grid(div_align(threadsX, threadsPerBlock), threadsY);
    RGBA_to_YUV422<<<grid, block, 0, stream>>>(texture, Y, U, V, pitchY, pitchUV, scale, aligned_viewport, (cuda_color_t *) color_matrix.get());
    return CU_CHECK_IGNORE(cudaGetLastError(), "RGBA_to_YUV422 failed");
  }

  int sws_t::convert_yuv422_10bit(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream) {
    return convert_yuv422_10bit(Y, U, V, pitchY, pitchUV, texture, stream, viewport);
  }

  int sws_t::convert_yuv422_10bit(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitchY, std::uint32_t pitchUV, cudaTextureObject_t texture, stream_t::pointer stream, const viewport_t &requested_viewport) {
    auto aligned_viewport = requested_viewport;
    aligned_viewport.offsetX &= ~1;
    aligned_viewport.width &= ~1;
    const int threadsX = aligned_viewport.width / 2;
    const int threadsY = aligned_viewport.height;
    dim3 block(threadsPerBlock);
    dim3 grid(div_align(threadsX, threadsPerBlock), threadsY);
    RGBA_to_YUV422_10bit<<<grid, block, 0, stream>>>(texture, Y, U, V, pitchY, pitchUV, scale, aligned_viewport, (cuda_color_t *) color_matrix.get());
    return CU_CHECK_IGNORE(cudaGetLastError(), "RGBA_to_YUV422_10bit failed");
  }

  int sws_t::convert_yuv444(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitch, cudaTextureObject_t texture, stream_t::pointer stream, const viewport_t &viewport) {
    int threadsX = viewport.width;
    int threadsY = viewport.height;

    dim3 block(threadsPerBlock);
    dim3 grid(div_align(threadsX, threadsPerBlock), threadsY);

    RGBA_to_YUV444<<<grid, block, 0, stream>>>(
      texture,
      Y,
      U,
      V,
      pitch,
      scale,
      viewport,
      (cuda_color_t *) color_matrix.get()
    );

    return CU_CHECK_IGNORE(cudaGetLastError(), "RGBA_to_YUV444 failed");
  }

  int sws_t::convert_yuv444_10bit(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitch, cudaTextureObject_t texture, stream_t::pointer stream) {
    return convert_yuv444_10bit(Y, U, V, pitch, texture, stream, viewport);
  }

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
                                   stream_t::pointer stream) {
    constexpr int threads_per_block = 16;
    const dim3 block(threads_per_block, threads_per_block);
    const dim3 grid(div_align(destination_width, threads_per_block),
                    div_align(destination_height, threads_per_block));
    XRGB10_to_identity_YUV444_10bit<<<grid, block, 0, stream>>>(
      reinterpret_cast<const std::uint8_t *>(source), source_pitch,
      source_width, source_height, Y, U, V, destination_pitch,
      destination_width, destination_height);
    return CU_CHECK_IGNORE(cudaGetLastError(),
                           "XRGB10_to_identity_YUV444_10bit failed");
  }

  int sws_t::convert_yuv444_10bit(std::uint8_t *Y, std::uint8_t *U, std::uint8_t *V, std::uint32_t pitch, cudaTextureObject_t texture, stream_t::pointer stream, const viewport_t &viewport) {
    const int threadsX = viewport.width;
    const int threadsY = viewport.height;

    dim3 block(threadsPerBlock);
    dim3 grid(div_align(threadsX, threadsPerBlock), threadsY);

    RGBA_to_YUV444_10bit<<<grid, block, 0, stream>>>(
      texture,
      Y,
      U,
      V,
      pitch,
      scale,
      viewport,
      (cuda_color_t *) color_matrix.get()
    );

    return CU_CHECK_IGNORE(cudaGetLastError(), "RGBA_to_YUV444_10bit failed");
  }

  void sws_t::apply_colorspace(const video::sunshine_colorspace_t &colorspace) {
    auto color_p = video::color_vectors_from_colorspace(colorspace, true);
    CU_CHECK_IGNORE(cudaMemcpy(color_matrix.get(), color_p, sizeof(video::color_t), cudaMemcpyHostToDevice), "Couldn't copy color matrix to cuda");
  }

  int sws_t::load_ram(platf::img_t &img, cudaArray_t array) {
    return CU_CHECK_IGNORE(cudaMemcpy2DToArray(array, 0, 0, img.data, img.row_pitch, img.width * img.pixel_pitch, img.height, cudaMemcpyHostToDevice), "Couldn't copy to cuda array");
  }

  #if defined(SUNSHINE_TESTS)
  bool test_identity_gbr_8bit_conversion() {
    constexpr int width = 4;
    constexpr int height = 1;
    constexpr std::uint32_t pitch = width;
    std::uint8_t source[] = {
      0, 0, 0, 255,
      255, 255, 255, 255,
      255, 0, 0, 255,
      0, 128, 255, 255,
    };

    auto texture = tex_t::make(height, width * 4);
    auto converter = sws_t::make(width, height, width, height, width * 4);
    auto stream = make_stream();
    if (!texture || !converter || !stream) {
      return false;
    }

    converter->apply_colorspace({video::colorspace_e::identity_gbr, true, 8});

    platf::img_t image;
    image.data = source;
    image.width = width;
    image.height = height;
    image.pixel_pitch = 4;
    image.row_pitch = width * image.pixel_pitch;

    void *destination = nullptr;
    if (cudaMalloc(&destination, pitch * height * 3) != cudaSuccess) {
      return false;
    }

    const auto cleanup = std::unique_ptr<void, freeCudaPtr_t> {destination};
    auto *base = static_cast<std::uint8_t *>(destination);
    if (converter->load_ram(image, texture->array) ||
        converter->convert_yuv444(base, base + pitch, base + pitch * 2, pitch, texture->texture.point, stream.get()) ||
        cudaStreamSynchronize(stream.get()) != cudaSuccess) {
      return false;
    }

    std::uint8_t actual[width * 3] {};
    if (cudaMemcpy(actual, destination, sizeof(actual), cudaMemcpyDeviceToHost) != cudaSuccess) {
      return false;
    }

    constexpr std::uint8_t expected[] = {
      0, 255, 0, 128,
      0, 255, 255, 0,
      0, 255, 0, 255,
    };
    return std::equal(std::begin(actual), std::end(actual), std::begin(expected));
  }

  bool test_identity_gbr_10bit_conversion() {
    constexpr int width = 4;
    constexpr int height = 1;
    constexpr std::uint32_t pitch = width * sizeof(std::uint16_t);
    std::uint8_t source[] = {
      0, 0, 0, 255,
      255, 255, 255, 255,
      255, 0, 0, 255,
      0, 128, 255, 255,
    };

    auto texture = tex_t::make(height, width * 4);
    auto converter = sws_t::make(width, height, width, height, width * 4);
    auto stream = make_stream();
    if (!texture || !converter || !stream) {
      return false;
    }

    converter->apply_colorspace({video::colorspace_e::identity_gbr, true, 10});

    platf::img_t image;
    image.data = source;
    image.width = width;
    image.height = height;
    image.pixel_pitch = 4;
    image.row_pitch = width * image.pixel_pitch;

    void *destination = nullptr;
    if (cudaMalloc(&destination, pitch * height * 3) != cudaSuccess) {
      return false;
    }

    const auto cleanup = std::unique_ptr<void, freeCudaPtr_t> {destination};
    auto *base = static_cast<std::uint8_t *>(destination);
    if (converter->load_ram(image, texture->array) ||
        converter->convert_yuv444_10bit(base, base + pitch, base + pitch * 2, pitch, texture->texture.point, stream.get()) ||
        cudaStreamSynchronize(stream.get()) != cudaSuccess) {
      return false;
    }

    std::uint16_t actual[width * 3] {};
    if (cudaMemcpy(actual, destination, sizeof(actual), cudaMemcpyDeviceToHost) != cudaSuccess) {
      return false;
    }

    constexpr std::uint16_t maximum = 1023 << 6;
    constexpr std::uint16_t midpoint = 514 << 6;
    constexpr std::uint16_t expected[] = {
      0, maximum, 0, midpoint,
      0, maximum, maximum, 0,
      0, maximum, 0, maximum,
    };
    return std::equal(std::begin(actual), std::end(actual), std::begin(expected));
  }
  #endif

}  // namespace cuda
