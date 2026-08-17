import React from 'react';

/**
 * ScoreGauge Component
 * Clean SVG radial arc visualizing the authoritative 0-100 security score and letter grade.
 *
 * @param {Object} props
 * @param {number|null} props.score - 0 to 100
 * @param {string|null} props.grade - 'A', 'B', 'C', 'D', 'F'
 */
export default function ScoreGauge({ score = 0, grade = 'N/A' }) {
  const safeScore = typeof score === 'number' && !isNaN(score) ? Math.min(100, Math.max(0, score)) : 0;

  // SVG circular arc math
  const radius = 64;
  const strokeWidth = 10;
  const normalizedRadius = radius - strokeWidth / 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const strokeDashoffset = circumference - (safeScore / 100) * circumference;

  const getGradeColor = (g) => {
    switch (g) {
      case 'A':
        return '#22c55e';
      case 'B':
        return '#facc15';
      case 'C':
        return '#f59e0b';
      case 'D':
        return '#f97316';
      case 'F':
      default:
        return '#ef4444';
    }
  };

  const gradeColor = getGradeColor(grade);

  return (
    <div
      className="score-gauge-wrapper"
      role="img"
      aria-label={`Security score: ${score !== null ? score : '--'} out of 100, Grade ${grade || 'N/A'}`}
    >
      <div className="gauge-svg-container">
        <svg height={radius * 2} width={radius * 2} className="gauge-svg" aria-hidden="true">
          {/* Background circle track */}
          <circle
            stroke="#262626"
            fill="transparent"
            strokeWidth={strokeWidth}
            r={normalizedRadius}
            cx={radius}
            cy={radius}
          />
          {/* Active progress arc */}
          <circle
            stroke={gradeColor}
            fill="transparent"
            strokeWidth={strokeWidth}
            strokeDasharray={`${circumference} ${circumference}`}
            style={{ strokeDashoffset }}
            strokeLinecap="round"
            r={normalizedRadius}
            cx={radius}
            cy={radius}
            className="gauge-arc"
          />
        </svg>
        <div className="gauge-center-content">
          <span className="gauge-score-value">{score !== null ? score : '--'}</span>
          <span className="gauge-score-denom">/ 100</span>
        </div>
      </div>

      <div className="gauge-grade-badge" style={{ borderColor: gradeColor, color: gradeColor }}>
        <span className="grade-letter mono">{grade || 'N/A'}</span>
      </div>
    </div>
  );
}
