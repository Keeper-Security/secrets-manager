import typescript from "rollup-plugin-typescript2"
import pkg from './package.json'
import sourcemaps from "rollup-plugin-sourcemaps";
import versionInjector from "rollup-plugin-version-injector";

export default [
    {
        input: 'src/browser/index.ts',
        output: [
            {
                file: pkg.browser,
                format: 'es',
                sourcemap: true
            },
        ],
        external: [
            ...Object.keys(pkg.dependencies || {}),
            "protobufjs/minimal"
        ],
        plugins: [
            typescript({
                tsconfig: "tsconfig.rollup.json"
            }),
            sourcemaps(),
            versionInjector()
        ]
    },
    {
        input: 'src/node/index.ts',
        output: [
            {
                file: pkg.main,
                format: 'cjs',
                sourcemap: true
            }
        ],
        external: [
            ...Object.keys(pkg.dependencies || {}),
            "crypto", "constants", "https", "fs"
        ],
        plugins: [
            typescript({
                tsconfig: "tsconfig.rollup.json"
            }),
            sourcemaps(),
            versionInjector()
        ]
    }
];
