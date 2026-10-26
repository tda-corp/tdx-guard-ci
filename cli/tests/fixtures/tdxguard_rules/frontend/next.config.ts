import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  images: {
    remotePatterns: [
      // ruleid: javascript.nextjs-image-any-remote-host
      { protocol: "https", hostname: "**" },
      // ok: javascript.nextjs-image-any-remote-host
      { protocol: "https", hostname: "*.googleusercontent.com" },
      // ok: javascript.nextjs-image-any-remote-host
      { protocol: "https", hostname: "storage.googleapis.com", pathname: "/sisuta-assets/**" },
    ],
  },
};

export default nextConfig;
