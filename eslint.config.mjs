import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FlatCompat } from '@eslint/eslintrc';

const compat = new FlatCompat({ baseDirectory: dirname(fileURLToPath(import.meta.url)) });
const config = [...compat.extends('next/core-web-vitals', 'next/typescript')];
const finalConfig = [
  ...config,
  { files: ['**/*.js'], rules: { '@typescript-eslint/no-require-imports': 'off' } },
  { ignores: ['.next/**', 'out/**', 'build/**', 'next-env.d.ts'] },
];
export default finalConfig;
