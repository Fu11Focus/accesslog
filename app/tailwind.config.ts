// tailwind.config.js
export default {
    content: [
        './slices/**/*.{vue,ts,js}',
    ],
    theme: {
        extend: {
            colors: {
                brand: {
                    dark: '#37524D',
                    light: '#336357',
            }
            },
            fontFamily: {
                oneday: ['OneDay', 'sans-serif'],
                montserrat: ['Montserrat', 'sans-serif'],
            },
        },
    },
}
