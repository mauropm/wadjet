/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      spacing: {
        '4.5': '1.125rem',
        '5.5': '1.375rem',
        '9.5': '2.375rem',
      },
      colors: {
        // WADJET brand palette
        base: '#0B0F0E', // page background (deep charcoal)
        panel: '#111614', // sidebar / sections
        raised: '#171D1B', // cards, panels
        line: '#243029', // hairline borders
        ink: '#F4F1EA', // off-white text
        mute: '#9BA8A0', // muted text
        accent: {
          DEFAULT: '#10B981', // emerald
          soft: '#34D399',
        },
        gold: '#C9A227', // muted gold secondary
        sev: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#EAB308',
          low: '#3B82F6',
          info: '#64748B',
        },
      },
      fontFamily: {
        sans: [
          'Inter',
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'sans-serif',
        ],
        mono: [
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Consolas',
          '"Liberation Mono"',
          'monospace',
        ],
      },
      borderRadius: {
        xl: '0.875rem',
        '2xl': '1.125rem',
      },
      boxShadow: {
        panel: '0 1px 0 0 rgba(244,241,234,0.03) inset, 0 12px 40px -12px rgba(0,0,0,0.6)',
        glow: '0 0 0 1px rgba(16,185,129,0.25), 0 8px 32px -8px rgba(16,185,129,0.18)',
      },
      keyframes: {
        'fade-in': {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        'slide-in-right': {
          from: { transform: 'translateX(100%)' },
          to: { transform: 'translateX(0)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-400px 0' },
          '100%': { backgroundPosition: '400px 0' },
        },
        'pulse-dot': {
          '0%,100%': { opacity: '1' },
          '50%': { opacity: '0.35' },
        },
      },
      animation: {
        'fade-in': 'fade-in 150ms ease-out',
        'slide-in-right': 'slide-in-right 180ms cubic-bezier(0.32,0.72,0,1)',
        shimmer: 'shimmer 1.4s linear infinite',
        'pulse-dot': 'pulse-dot 1.2s ease-in-out infinite',
      },
      transitionDuration: {
        DEFAULT: '150ms',
      },
    },
  },
  plugins: [],
};
