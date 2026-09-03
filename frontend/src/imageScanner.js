import * as faceapi from 'face-api.js';

// Model paths — served from /public/models/ by Vite static server
const MODEL_URL = '/models/';

// Load the TinyFaceDetector model once and cache it
let faceDetectionModelsLoaded = false;

export async function loadFaceModels() {
  if (faceDetectionModelsLoaded) return;

  try {
    await faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL);
    faceDetectionModelsLoaded = true;
  } catch (err) {
    console.warn('face-api.js model load warning:', err);
    faceDetectionModelsLoaded = true;
  }
}

// Supported image types for the scanner
const SUPPORTED_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
const THUMBNAIL_SIZE = 72;

// -----------------------------------------------------------
// Layer 1: Client-Side Face Redaction / Mosaic Pixelation
// -----------------------------------------------------------
export function redactFaceFromImage(file, detectionBox) {
  // detectionBox = { x, y, width, height }
  return new Promise(async (resolve) => {
    try {
      const img = new Image();
      const objectUrl = URL.createObjectURL(file);
      await new Promise((res, rej) => {
        img.onload = res;
        img.onerror = rej;
        img.src = objectUrl;
      });

      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, img.width, img.height);

      if (detectionBox && detectionBox.width > 0 && detectionBox.height > 0) {
        const patchW = 8;
        const patchH = 8;
        const tempCanvas = document.createElement('canvas');
        tempCanvas.width = patchW;
        tempCanvas.height = patchH;
        const tempCtx = tempCanvas.getContext('2d');

        // Draw face region tiny
        tempCtx.drawImage(
          canvas,
          detectionBox.x, detectionBox.y, detectionBox.width, detectionBox.height,
          0, 0, patchW, patchH
        );

        // Upscale back without smoothing -> heavy mosaic
        ctx.imageSmoothingEnabled = false;
        ctx.drawImage(
          tempCanvas,
          0, 0, patchW, patchH,
          detectionBox.x, detectionBox.y, detectionBox.width, detectionBox.height
        );
        ctx.imageSmoothingEnabled = true;

        // Draw privacy tag
        ctx.fillStyle = 'rgba(239, 68, 68, 0.85)';
        ctx.fillRect(detectionBox.x, Math.max(0, detectionBox.y - 18), 120, 18);
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 10px monospace';
        ctx.fillText('BIOMETRIC REDACTED', detectionBox.x + 4, Math.max(12, detectionBox.y - 5));

        ctx.strokeStyle = '#ef4444';
        ctx.lineWidth = 2;
        ctx.strokeRect(
          detectionBox.x, detectionBox.y,
          detectionBox.width, detectionBox.height
        );
      }

      // Convert to blob and File
      const sanitizedDataUrl = canvas.toDataURL('image/jpeg', 0.85);
      const sanitizedBlob = await (await fetch(sanitizedDataUrl)).blob();
      const sanitizedFile = new File([sanitizedBlob], file.name, { type: 'image/jpeg' });

      // Build 72px thumbnail
      const thumbCanvas = document.createElement('canvas');
      thumbCanvas.width = THUMBNAIL_SIZE;
      thumbCanvas.height = THUMBNAIL_SIZE;
      const thumbCtx = thumbCanvas.getContext('2d');
      thumbCtx.drawImage(canvas, 0, 0, img.width, img.height, 0, 0, THUMBNAIL_SIZE, THUMBNAIL_SIZE);
      const sanitizedThumbnail = thumbCanvas.toDataURL('image/jpeg', 0.6);

      URL.revokeObjectURL(objectUrl);

      resolve({
        sanitizedFile,
        sanitizedDataUrl,
        sanitizedThumbnail,
      });
    } catch (err) {
      console.error('redactFaceFromImage error:', err);
      resolve({
        sanitizedFile: file,
        sanitizedDataUrl: '',
        sanitizedThumbnail: '',
      });
    }
  });
}

// scanImageFile — detect faces in a File object, return result object
export async function scanImageFile(file) {
  if (file.type && file.type.includes('heic')) {
    return {
      hasFace: false,
      faceCount: 0,
      thumbnailDataUrl: '',
      imageDimensions: { w: 0, h: 0 },
      scanTimeMs: 0,
      error: 'HEIC format not supported — please use JPEG, PNG, or WEBP',
    };
  }

  const MAX_DIMENSION = 640;
  let resizedBlob = file;
  let origW = 0;
  let origH = 0;
  let scaleRatio = 1;

  try {
    const url = URL.createObjectURL(file);
    const img = new Image();
    await new Promise((res, rej) => {
      img.onload = res;
      img.onerror = rej;
      img.src = url;
    });

    origW = img.naturalWidth || img.width;
    origH = img.naturalHeight || img.height;
    URL.revokeObjectURL(url);

    if (origW > MAX_DIMENSION || origH > MAX_DIMENSION) {
      scaleRatio = Math.min(MAX_DIMENSION / origW, MAX_DIMENSION / origH);
      const newW = Math.round(origW * scaleRatio);
      const newH = Math.round(origH * scaleRatio);

      const canvas = document.createElement('canvas');
      canvas.width = newW;
      canvas.height = newH;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, newW, newH);

      const resizedDataUrl = canvas.toDataURL(file.type || 'image/jpeg', 0.85);
      resizedBlob = await (await fetch(resizedDataUrl)).blob();
    }
  } catch (e) {}

  await loadFaceModels();
  const startTime = performance.now();

  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  const img = new Image();
  const objectUrl = URL.createObjectURL(resizedBlob);

  await new Promise((res, rej) => {
    img.onload = res;
    img.onerror = rej;
    img.src = objectUrl;
  });

  canvas.width = img.width;
  canvas.height = img.height;
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

  let hasFace = false;
  let faceCount = 0;
  let detectionBox = null;
  let originalFaceBox = null;

  try {
    const detection = await faceapi.detectSingleFace(
      canvas,
      new faceapi.TinyFaceDetectorOptions({ inputSize: 320, scoreThreshold: 0.5 })
    );

    if (detection && detection.box) {
      hasFace = true;
      faceCount = 1;
      detectionBox = {
        x: detection.box.x,
        y: detection.box.y,
        width: detection.box.width,
        height: detection.box.height,
      };
      // Map back to original dimensions
      originalFaceBox = {
        x: Math.round(detectionBox.x / (scaleRatio || 1)),
        y: Math.round(detectionBox.y / (scaleRatio || 1)),
        width: Math.round(detectionBox.width / (scaleRatio || 1)),
        height: Math.round(detectionBox.height / (scaleRatio || 1)),
      };
    }
  } catch (err) {
    console.warn('Face detection error:', err);
  }

  URL.revokeObjectURL(objectUrl);
  const scanTimeMs = Math.round(performance.now() - startTime);

  // Generate thumbnail of raw image
  let thumbnailDataUrl = '';
  try {
    const thumbCanvas = document.createElement('canvas');
    thumbCanvas.width = THUMBNAIL_SIZE;
    thumbCanvas.height = THUMBNAIL_SIZE;
    const thumbCtx = thumbCanvas.getContext('2d');
    thumbCtx.drawImage(canvas, 0, 0, canvas.width, canvas.height, 0, 0, THUMBNAIL_SIZE, THUMBNAIL_SIZE);
    thumbnailDataUrl = thumbCanvas.toDataURL('image/jpeg', 0.6);
  } catch (e) {}

  // If face detected, generate sanitized version upfront
  let redactedResult = null;
  if (hasFace && originalFaceBox) {
    redactedResult = await redactFaceFromImage(file, originalFaceBox);
  }

  return {
    hasFace,
    faceCount,
    detectionBox: originalFaceBox,
    thumbnailDataUrl,
    rawThumbnail: thumbnailDataUrl,
    sanitizedThumbnail: redactedResult ? redactedResult.sanitizedThumbnail : thumbnailDataUrl,
    sanitizedDataUrl: redactedResult ? redactedResult.sanitizedDataUrl : '',
    sanitizedFile: redactedResult ? redactedResult.sanitizedFile : file,
    imageDimensions: { w: origW || img.width, h: origH || img.height },
    scanTimeMs,
  };
}