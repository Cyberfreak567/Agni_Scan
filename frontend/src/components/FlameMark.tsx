interface FlameMarkProps {
  compact?: boolean;
}

export function FlameMark({ compact = false }: FlameMarkProps) {
  return (
    <div className={`brand-mark ${compact ? "compact" : ""}`} aria-hidden="true">
      <div className="brand-fire-aura" />
      <svg className="flame-logo" viewBox="0 0 220 260" role="presentation">
        <defs>
          <linearGradient id="flameOuter" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#ff3d00" />
            <stop offset="55%" stopColor="#ff6a00" />
            <stop offset="100%" stopColor="#a60017" />
          </linearGradient>
          <linearGradient id="flameMid" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#ffd55c" />
            <stop offset="40%" stopColor="#ffb126" />
            <stop offset="100%" stopColor="#ff5a00" />
          </linearGradient>
          <linearGradient id="flameInner" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#fff8d2" />
            <stop offset="55%" stopColor="#ffd75b" />
            <stop offset="100%" stopColor="#ff9a1a" />
          </linearGradient>
        </defs>

        <path
          className="flame-shape flame-shape-outer"
          fill="url(#flameOuter)"
          d="M110 14c18 26 23 47 18 69 26-22 44-17 53 17 10 33 4 50-8 74 20-10 31-2 34 21 5 38-23 61-40 70-17 10-36 14-56 14-43 0-72-14-90-36-13-16-19-35-17-57 1-18 11-31 28-39-18-39-9-73 31-102 9-6 18-17 28-31 4 11 8 25 6 39 6-8 10-23 13-39Z"
        />
        <path
          className="flame-shape flame-shape-mid"
          fill="url(#flameMid)"
          d="M112 42c8 19 8 35 1 49 19-13 33-11 40 9 10 25 8 43-6 61 18-6 27 1 28 20 2 27-19 44-34 51-13 7-26 11-43 11-33 0-57-12-70-31-11-15-11-35 1-49-11-32-2-54 30-73 10-7 19-19 27-48 9 14 14 27 14 40 4-8 8-22 12-40Z"
        />
        <path
          className="flame-shape flame-shape-inner"
          fill="url(#flameInner)"
          d="M110 70c5 13 5 25 0 35 11-7 21-6 28 6 8 14 8 27 0 40 13-2 19 6 18 19-1 21-17 33-28 38-11 5-20 7-33 7-26 0-42-8-53-24-10-14-9-28 2-39-7-20-2-34 16-44 12-7 22-18 32-38 8 11 12 21 11 30 2-6 4-16 7-30Z"
        />
        <path
          className="flame-vein flame-vein-left"
          fill="none"
          stroke="#ffef9a"
          strokeWidth="4"
          strokeLinecap="round"
          d="M72 96c-18 24-21 44-12 61 8 16 10 29 4 40"
        />
        <path
          className="flame-vein flame-vein-center"
          fill="none"
          stroke="#fff7cb"
          strokeWidth="5"
          strokeLinecap="round"
          d="M111 76c12 20 14 39 7 56-6 12-8 24-6 36 3 16-1 29-11 41"
        />
        <path
          className="flame-vein flame-vein-right"
          fill="none"
          stroke="#ffd86e"
          strokeWidth="4"
          strokeLinecap="round"
          d="M146 92c16 19 20 37 11 53-7 13-8 28-1 44"
        />
      </svg>
      <div className="brand-spark spark-one" />
      <div className="brand-spark spark-two" />
      <div className="brand-spark spark-three" />
      <div className="brand-ring ring-one" />
      <div className="brand-ring ring-two" />
    </div>
  );
}
