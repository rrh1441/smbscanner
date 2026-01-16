// LOCAL ONLY - Object store for local file storage
// GCP Cloud Storage implementation removed for OSS

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { createModuleLogger } from './logger.js';

const log = createModuleLogger('objectStore');

const LOCAL_STORAGE_DIR = process.env.LOCAL_STORAGE_DIR || './data/objects';

/**
 * Save an object to local storage
 */
export async function saveObject(bucket: string, key: string, data: Buffer | string): Promise<string> {
  const dir = path.join(LOCAL_STORAGE_DIR, bucket);
  await fs.mkdir(dir, { recursive: true });
  const filePath = path.join(dir, key);
  await fs.writeFile(filePath, data);
  log.debug({ bucket, key, size: typeof data === 'string' ? data.length : data.byteLength }, 'Saved object locally');
  return filePath;
}

/**
 * Read an object from local storage
 */
export async function getObject(bucket: string, key: string): Promise<Buffer | null> {
  try {
    const filePath = path.join(LOCAL_STORAGE_DIR, bucket, key);
    return await fs.readFile(filePath);
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

/**
 * Delete an object from local storage
 */
export async function deleteObject(bucket: string, key: string): Promise<void> {
  try {
    const filePath = path.join(LOCAL_STORAGE_DIR, bucket, key);
    await fs.unlink(filePath);
    log.debug({ bucket, key }, 'Deleted object');
  } catch (error: any) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
}

/**
 * List objects in a bucket/prefix
 */
export async function listObjects(bucket: string, prefix?: string): Promise<string[]> {
  try {
    const dir = path.join(LOCAL_STORAGE_DIR, bucket, prefix || '');
    const files = await fs.readdir(dir);
    return files;
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      return [];
    }
    throw error;
  }
}

/**
 * Check if an object exists
 */
export async function objectExists(bucket: string, key: string): Promise<boolean> {
  try {
    const filePath = path.join(LOCAL_STORAGE_DIR, bucket, key);
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}
