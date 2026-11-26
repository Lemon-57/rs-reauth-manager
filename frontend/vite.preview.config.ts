import { mergeConfig } from 'vite'
import base from './vite.config'
export default mergeConfig(base, { cacheDir: '../../preview-cache' })
