/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#070d0f',
        panel: '#0b1214',
        surface: '#0f1415',
        tabbar: '#0a0c0c',
        border: 'rgba(25, 211, 217, 0.14)',
        accent: {
          DEFAULT: '#19d3d9',
          fill: '#0b2e30',
          border: '#1a8c90',
        },
        active: {
          circle: '#0f4a4d',
        },
        text: '#e8eeee',
        muted: '#7d8a8c',
        dim: '#5d6c6e',
        danger: '#d94848',
      },
      fontFamily: {
        mono: ['"Space Mono"', 'monospace', 'ui-monospace'],
        sans: ['"Space Grotesk"', 'sans-serif'],
      },
      letterSpacing: {
        hero: '0.06em',
        subtitle: '0.35em',
        label: '0.2em',
        widest: '0.25em',
      },
      borderRadius: {
        pill: '28px',
        panel: '24px',
        square: '2px',
      },
      boxShadow: {
        glow: '0 0 15px rgba(25, 211, 217, 0.25)',
        'glow-sm': '0 0 8px rgba(25, 211, 217, 0.3)',
      },
    },
  },
  plugins: [],
};
