import React from 'react';

export type TernatioLogoVariant = 'flat' | 'metallic' | 'contour' | 'shield' | 'circle';

interface TernatioLogoProps {
  variant?: TernatioLogoVariant;
  size?: 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  showWordmark?: boolean;
  showTagline?: boolean;
  className?: string;
  themeColor?: 'light' | 'dark' | 'gold' | 'navy' | 'auto';
}

/**
 * Ternatio BJJ Official Geometric Emblem & Wordmark
 * Recreated accurately from the official brand identity manual.
 */
export const TernatioLogo: React.FC<TernatioLogoProps> = ({
  variant = 'flat',
  size = 'md',
  showWordmark = true,
  showTagline = false,
  className = '',
  themeColor = 'auto'
}) => {
  // Dimension mapping
  const sizeMap = {
    sm: { symbol: 24, text: 'text-sm', bjj: 'text-[9px]', sub: 'text-[7px]' },
    md: { symbol: 36, text: 'text-base', bjj: 'text-[10px]', sub: 'text-[8px]' },
    lg: { symbol: 48, text: 'text-xl', bjj: 'text-xs', sub: 'text-[9px]' },
    xl: { symbol: 64, text: 'text-2xl', bjj: 'text-sm', sub: 'text-[10px]' },
    '2xl': { symbol: 88, text: 'text-3xl', bjj: 'text-base', sub: 'text-xs' }
  };

  const currentSize = sizeMap[size] || sizeMap.md;

  // Color profiles
  const isGold = themeColor === 'gold' || variant === 'metallic';
  const isNavy = themeColor === 'navy';
  const isLight = themeColor === 'light';

  const fillPrimary = isGold
    ? 'url(#ternatioGoldGrad)'
    : isNavy
    ? '#1E3A8A'
    : isLight
    ? '#FFFFFF'
    : 'currentColor';

  const strokeColor = isGold ? '#D4AF37' : isNavy ? '#3B82F6' : 'currentColor';

  return (
    <div className={`inline-flex items-center gap-3 select-none ${className}`}>
      {/* SVG Symbol */}
      <svg
        width={currentSize.symbol}
        height={currentSize.symbol}
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="shrink-0 drop-shadow-sm transition-transform duration-300 hover:scale-105"
      >
        <defs>
          {/* Metallic Gold Gradient */}
          <linearGradient id="ternatioGoldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#F5D38A" />
            <stop offset="50%" stopColor="#C5A059" />
            <stop offset="100%" stopColor="#9E7B35" />
          </linearGradient>

          {/* Platinum / Metallic Silver Gradient */}
          <linearGradient id="ternatioSilverGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#FFFFFF" />
            <stop offset="50%" stopColor="#CBD5E1" />
            <stop offset="100%" stopColor="#94A3B8" />
          </linearGradient>

          {/* Deep Navy / Electric Gradient */}
          <linearGradient id="ternatioNavyGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#60A5FA" />
            <stop offset="100%" stopColor="#1E3A8A" />
          </linearGradient>
        </defs>

        {/* Circular Seal Variant */}
        {variant === 'circle' && (
          <>
            <circle cx="50" cy="50" r="46" stroke={strokeColor} strokeWidth="3" opacity="0.4" />
            <circle cx="50" cy="50" r="41" stroke={strokeColor} strokeWidth="1.5" strokeDasharray="3 3" opacity="0.6" />
          </>
        )}

        {/* Shield Variant */}
        {variant === 'shield' && (
          <path
            d="M50 8 L88 20 V48 C88 72 50 92 50 92 C50 92 12 72 12 48 V20 L50 8 Z"
            stroke={strokeColor}
            strokeWidth="3.5"
            fill="none"
            opacity="0.85"
          />
        )}

        {/* Ternatio Geometric "T" Wings & Spine */}
        {/* Top Horizontal Bar with Beveled Ends */}
        <polygon
          points="15,22 85,22 75,32 25,32"
          fill={fillPrimary}
        />

        {/* Center Vertical Column / Sword Spine */}
        <polygon
          points="44,34 56,34 54,82 50,88 46,82"
          fill={fillPrimary}
        />

        {/* Left Wing Facet */}
        <polygon
          points="27,35 41,35 41,68 33,56 27,42"
          fill={fillPrimary}
          opacity="0.9"
        />

        {/* Right Wing Facet */}
        <polygon
          points="59,35 73,35 73,42 67,56 59,68"
          fill={fillPrimary}
          opacity="0.9"
        />

        {/* Inner Chevron Accent */}
        <polygon
          points="46,37 54,37 50,45"
          fill={isGold ? '#FFFFFF' : '#0F172A'}
          opacity="0.4"
        />
      </svg>

      {/* Wordmark */}
      {showWordmark && (
        <div className="flex flex-col leading-none">
          <span 
            className={`font-black tracking-widest uppercase font-mono ${currentSize.text} ${
              isGold ? 'text-amber-400 drop-shadow-sm' : ''
            }`}
            style={{ letterSpacing: '0.18em' }}
          >
            TERNATIO
          </span>

          <div className="flex items-center gap-1.5 mt-0.5">
            <span className="h-[1px] w-3 bg-current opacity-40"></span>
            <span 
              className={`font-bold tracking-widest ${currentSize.bjj} uppercase opacity-90`}
              style={{ letterSpacing: '0.3em' }}
            >
              BJJ
            </span>
            <span className="h-[1px] w-3 bg-current opacity-40"></span>
          </div>

          {showTagline && (
            <span className={`font-semibold tracking-wider text-slate-400 mt-1 uppercase ${currentSize.sub}`}>
              Disciplina • Respeito • Evolução
            </span>
          )}
        </div>
      )}
    </div>
  );
};
