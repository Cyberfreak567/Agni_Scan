interface SpinnerProps {
  size?: number;
}

export function Spinner({ size = 18 }: SpinnerProps) {
  return (
    <span
      className="inline-block animate-spin rounded-full border-2 border-white/40 border-t-white"
      style={{ width: size, height: size }}
    />
  );
}
