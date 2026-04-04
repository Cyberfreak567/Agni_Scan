/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: "#050b11",
        panel: "rgba(10, 22, 33, 0.78)",
        ink: "#f4f1ea",
        muted: "#9fb0bc",
        accent: "#ff7a2f",
        accentGlow: "#ffb347",
        neon: "#6ce5ff",
        good: "#4de2a8",
        warn: "#f6b13d",
        bad: "#ff6b6b",
        critical: "#ff3d5a",
      },
      boxShadow: {
        panel: "0 26px 80px rgba(0,0,0,0.38)",
        glow: "0 0 24px rgba(108,229,255,0.3), 0 0 36px rgba(255,122,47,0.25)",
      },
      backdropBlur: {
        xl: "20px",
      },
    },
  },
  plugins: [],
};
