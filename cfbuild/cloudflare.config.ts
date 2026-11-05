import { bindings, defineConfig, defineContainer, exports } from "cf/config";

import * as entrypoint from "./src/index.ts" with { type: "cf-worker" };

// A CPU-only Linux box for compiling CUDA/CUTLASS kernels (nvcc needs no GPU). The stable Sandbox image is pulled
// from Docker Hub, so no local Docker build is needed; the CUDA toolkit is installed into it at run time.
const builder = defineContainer({
  name: "okc-cuda-build",
  image: { reference: "docker.io/cloudflare/sandbox:0.12.14-python" },
  instanceType: "standard-4",
  maxInstances: 1,
});

export default defineConfig({
  worker: {
    name: "okc-cuda-build",
    compatibilityDate: "2026-10-01",
    entrypoint,
    exports: {
      Sandbox: exports.durableObject({ storage: "sqlite", container: builder }),
    },
    env: {
      Sandbox: bindings.durableObject({ worker: "okc-cuda-build", exportName: "Sandbox" }),
      BUILD_TOKEN: bindings.secret(),
    },
  },
  containers: [builder],
});
