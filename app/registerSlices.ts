import * as fs from 'fs';
export const registerSlices = (): string[] => {
    const slices = fs.readdirSync('./slices');
    if (!slices.length) return [];
    let result = [];
    for (const slice of slices) {
        if (fs.existsSync(`./slices/${slice}/nuxt.config.ts`)) {
            if (`${slice}` !== 'setup' && `${slice}` !== 'api') {
                result.push(`./slices/${slice}`);
            }
        } else {
            const subSlices = fs.readdirSync(`./slices/${slice}`);
            for (const subSlice of subSlices) {
                if (fs.existsSync(`./slices/${slice}/${subSlice}/nuxt.config.ts`)) {
                    if (`${slice}/${subSlice}` !== 'mobiflor/common') {
                        result.push(`./slices/${slice}/${subSlice}`);
                    }
                } else {
                    const subSubSlices = fs.readdirSync(`./slices/${slice}/${subSlice}`);
                    for (const subSubSlice of subSubSlices) {
                        if (fs.existsSync(`./slices/${slice}/${subSlice}/${subSubSlice}/nuxt.config.ts`)) {
                            if (`${slice}/${subSlice}/${subSubSlice}` === 'mobiflor/users/auth') {
                                continue;
                            }
                            result.push(`./slices/${slice}/${subSlice}/${subSubSlice}`);
                        }
                    }
                }
            }
        }
    }

    result = [...result];
    return result;
};
