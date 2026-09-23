/**
 * StegoCrypt Studio Web Client Application Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  // --- DOM Elements ---
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  // Cover Image (Hide Tab)
  const dropCoverZone = document.getElementById('drop-cover-zone');
  const coverFileInput = document.getElementById('cover-file-input');
  const coverPreviewCard = document.getElementById('cover-preview-card');
  const coverThumbImg = document.getElementById('cover-thumb-img');
  const coverFileName = document.getElementById('cover-file-name');
  const coverSpecsText = document.getElementById('cover-specs-text');
  const capacityMeterFill = document.getElementById('capacity-meter-fill');

  // Secret & Password Inputs
  const secretTextInput = document.getElementById('secret-text-input');
  const secretCharCounter = document.getElementById('secret-char-counter');
  const hidePassphraseInput = document.getElementById('hide-passphrase-input');
  const btnToggleHidePwd = document.getElementById('btn-toggle-hide-pwd');
  const btnRunHide = document.getElementById('btn-run-hide');

  // Stego Output Elements
  const hidePlaceholder = document.getElementById('hide-placeholder');
  const stegoOutputView = document.getElementById('stego-output-view');
  const stegoPreviewImg = document.getElementById('stego-preview-img');
  const metricPsnr = document.getElementById('metric-psnr');
  const metricSsim = document.getElementById('metric-ssim');
  const metricMse = document.getElementById('metric-mse');
  const metricCapacity = document.getElementById('metric-capacity');
  const metricPayloadSize = document.getElementById('metric-payload-size');
  const btnOpenDiffModal = document.getElementById('btn-open-diff-modal');
  const btnDownloadStego = document.getElementById('btn-download-stego');

  // Extract Tab Elements
  const dropExtractZone = document.getElementById('drop-extract-zone');
  const extractFileInput = document.getElementById('extract-file-input');
  const extractPreviewCard = document.getElementById('extract-preview-card');
  const extractThumbImg = document.getElementById('extract-thumb-img');
  const extractFileName = document.getElementById('extract-file-name');
  const extractSpecsText = document.getElementById('extract-specs-text');
  const extractPassphraseInput = document.getElementById('extract-passphrase-input');
  const btnToggleExtractPwd = document.getElementById('btn-toggle-extract-pwd');
  const btnRunExtract = document.getElementById('btn-run-extract');
  const extractPlaceholder = document.getElementById('extract-placeholder');
  const extractResultView = document.getElementById('extract-result-view');
  const recoveredTextDisplay = document.getElementById('recovered-text-display');
  const recoveredStatsText = document.getElementById('recovered-stats-text');
  const btnCopyRecovered = document.getElementById('btn-copy-recovered');

  // Modal Elements
  const diffModal = document.getElementById('diff-modal');
  const btnCloseDiffModal = document.getElementById('btn-close-diff-modal');
  const modalCoverImg = document.getElementById('modal-cover-img');
  const modalStegoImg = document.getElementById('modal-stego-img');
  const modalDiffImg = document.getElementById('modal-diff-img');

  const toastContainer = document.getElementById('toast-container');

  // State
  let currentCoverFile = null;
  let currentCoverCapacity = 0;
  let currentExtractFile = null;
  let lastCoverDataUrl = null;
  let lastStegoDataUrl = null;
  let lastDiffDataUrl = null;
  let copyTimeoutId = null;

  // =================================================================
  // Tab Navigation with ARIA State Management
  // =================================================================
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      const targetId = btn.getAttribute('data-tab');
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add('active');
      }
    });
  });

  // =================================================================
  // Toast Notifications
  // =================================================================
  function showToast(message, type = 'info') {
    if (!toastContainer) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icon = type === 'error' ? '⚠️' : (type === 'success' ? '✅' : 'ℹ️');
    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  // =================================================================
  // Password Visibility Toggle
  // =================================================================
  function setupPwdToggle(inputEl, btnEl) {
    if (!inputEl || !btnEl) return;
    btnEl.addEventListener('click', (e) => {
      e.preventDefault();
      if (inputEl.type === 'password') {
        inputEl.type = 'text';
        btnEl.textContent = '🙈';
        btnEl.setAttribute('title', 'Hide passphrase');
      } else {
        inputEl.type = 'password';
        btnEl.textContent = '👁️';
        btnEl.setAttribute('title', 'Show passphrase');
      }
    });
  }
  setupPwdToggle(hidePassphraseInput, btnToggleHidePwd);
  setupPwdToggle(extractPassphraseInput, btnToggleExtractPwd);

  // =================================================================
  // Secret Text Counter & Capacity Gauge
  // =================================================================
  function updateSecretCounter() {
    const text = secretTextInput.value;
    const bytes = new TextEncoder().encode(text).length;
    secretCharCounter.textContent = `${text.length.toLocaleString()} characters (${bytes.toLocaleString()} bytes)`;

    if (currentCoverCapacity > 0) {
      const pct = Math.min(100, Math.round((bytes / currentCoverCapacity) * 100));
      capacityMeterFill.style.width = `${pct}%`;
      if (pct > 90) {
        capacityMeterFill.style.background = 'var(--accent-rose)';
      } else {
        capacityMeterFill.style.background = 'linear-gradient(90deg, var(--accent-cyan), var(--accent-emerald))';
      }
    } else {
      capacityMeterFill.style.width = '0%';
    }
  }
  secretTextInput.addEventListener('input', updateSecretCounter);

  // =================================================================
  // Drag & Drop File Upload Handlers
  // =================================================================
  function setupDropZone(dropZoneEl, fileInputEl, onFileSelected) {
    if (!dropZoneEl || !fileInputEl) return;

    ['dragenter', 'dragover'].forEach(eventName => {
      dropZoneEl.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZoneEl.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropZoneEl.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZoneEl.classList.remove('dragover');
      });
    });

    dropZoneEl.addEventListener('drop', (e) => {
      const files = e.dataTransfer.files;
      if (files && files.length > 0) {
        onFileSelected(files[0]);
      }
    });

    fileInputEl.addEventListener('change', () => {
      if (fileInputEl.files && fileInputEl.files.length > 0) {
        onFileSelected(fileInputEl.files[0]);
      }
    });

    // Keyboard support for dropzone
    dropZoneEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInputEl.click();
      }
    });
  }

  // Cover Image Handler
  setupDropZone(dropCoverZone, coverFileInput, async (file) => {
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['png', 'bmp'].includes(ext)) {
      showToast('Only lossless PNG (.png) and BMP (.bmp) images are supported.', 'error');
      return;
    }

    currentCoverFile = file;
    coverFileName.textContent = file.name;
    
    // Read thumbnail preview
    const reader = new FileReader();
    reader.onload = (e) => {
      coverThumbImg.src = e.target.result;
      lastCoverDataUrl = e.target.result;
      coverPreviewCard.classList.add('visible');
    };
    reader.readAsDataURL(file);

    // Call Capacity API
    const formData = new FormData();
    formData.append('image', file);

    try {
      const res = await fetch('/api/capacity', { method: 'POST', body: formData });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Failed to analyze cover image' }));
        throw new Error(err.detail || 'Capacity calculation error');
      }
      const data = await res.json();
      currentCoverCapacity = data.capacity_bytes;
      coverSpecsText.textContent = `Dimensions: ${data.width} x ${data.height} (${data.mode}) | Max Usable Capacity: ${data.capacity_bytes.toLocaleString()} bytes (${data.capacity_kb} KB)`;
      updateSecretCounter();
      showToast(`Cover loaded: ${data.width}x${data.height} (${data.capacity_kb} KB carrier capacity)`, 'success');
    } catch (e) {
      showToast(`Failed to analyze cover image: ${e.message}`, 'error');
    }
  });

  // Extract Image Handler
  setupDropZone(dropExtractZone, extractFileInput, (file) => {
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['png', 'bmp'].includes(ext)) {
      showToast('Only lossless PNG (.png) and BMP (.bmp) images are supported.', 'error');
      return;
    }

    currentExtractFile = file;
    extractFileName.textContent = file.name;

    const reader = new FileReader();
    reader.onload = (e) => {
      extractThumbImg.src = e.target.result;
      extractPreviewCard.classList.add('visible');
    };
    reader.readAsDataURL(file);

    const img = new Image();
    img.onload = () => {
      extractSpecsText.textContent = `Dimensions: ${img.naturalWidth} x ${img.naturalHeight} | Format: ${ext.toUpperCase()}`;
    };
    img.src = URL.createObjectURL(file);
    showToast(`Stego image loaded: ${file.name}`, 'info');
  });

  // =================================================================
  // Run Encrypt & Hide Operation
  // =================================================================
  btnRunHide.addEventListener('click', async () => {
    if (!currentCoverFile) {
      showToast('Please select a lossless cover image first.', 'error');
      return;
    }
    const secretText = secretTextInput.value.trim();
    if (!secretText) {
      showToast('Please enter a secret message to conceal.', 'error');
      return;
    }
    const passphrase = hidePassphraseInput.value;
    if (!passphrase) {
      showToast('Please enter an encryption passphrase.', 'error');
      return;
    }

    btnRunHide.disabled = true;
    btnRunHide.innerHTML = '<span class="spinner"></span> <span>Encrypting &amp; Embedding LSBs...</span>';

    const formData = new FormData();
    formData.append('cover', currentCoverFile);
    formData.append('secret_text', secretText);
    formData.append('passphrase', passphrase);

    try {
      const res = await fetch('/api/hide', { method: 'POST', body: formData });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Encryption and embedding failed.' }));
        throw new Error(err.detail || 'Encryption and embedding failed.');
      }
      const data = await res.json();

      // Update Results
      hidePlaceholder.style.display = 'none';
      stegoOutputView.classList.add('visible');

      lastStegoDataUrl = data.stego_image_base64;
      lastDiffDataUrl = data.diff_image_base64;

      stegoPreviewImg.src = lastStegoDataUrl;
      btnDownloadStego.href = lastStegoDataUrl;
      btnDownloadStego.download = data.filename || 'stego_image.png';

      metricPsnr.textContent = `${data.psnr_db.toFixed(2)} dB`;
      metricSsim.textContent = data.ssim.toFixed(6);
      metricMse.textContent = data.mse.toFixed(6);
      metricCapacity.textContent = `${data.capacity_used_pct}%`;
      metricPayloadSize.textContent = `${data.encrypted_payload_bytes.toLocaleString()} bytes encrypted`;

      showToast(`Concealment complete! PSNR: ${data.psnr_db.toFixed(2)} dB (Imperceptible)`, 'success');

    } catch (e) {
      showToast(`Operation Failed: ${e.message}`, 'error');
    } finally {
      btnRunHide.disabled = false;
      btnRunHide.innerHTML = '<span class="btn-icon">⚡</span> <span class="btn-text">Encrypt &amp; Conceal Payload</span>';
    }
  });

  // =================================================================
  // Run Extract & Decrypt Operation
  // =================================================================
  btnRunExtract.addEventListener('click', async () => {
    if (!currentExtractFile) {
      showToast('Please select a stego image to extract from.', 'error');
      return;
    }
    const passphrase = extractPassphraseInput.value;
    if (!passphrase) {
      showToast('Please enter the decryption passphrase.', 'error');
      return;
    }

    btnRunExtract.disabled = true;
    btnRunExtract.innerHTML = '<span class="spinner"></span> <span>Extracting &amp; Authenticating Tag...</span>';

    const formData = new FormData();
    formData.append('stego_image', currentExtractFile);
    formData.append('passphrase', passphrase);

    try {
      const res = await fetch('/api/extract', { method: 'POST', body: formData });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Authentication or decryption failed.' }));
        throw new Error(err.detail || 'Decryption failed.');
      }
      const data = await res.json();

      extractPlaceholder.style.display = 'none';
      extractResultView.style.display = 'block';
      btnCopyRecovered.style.display = 'inline-flex';

      recoveredTextDisplay.textContent = data.recovered_text;
      recoveredStatsText.textContent = `✅ 128-bit AEAD Tag Verified | Recovered: ${data.length_characters.toLocaleString()} characters (${data.length_bytes.toLocaleString()} bytes)`;

      showToast('Payload extracted & authenticated successfully!', 'success');

    } catch (e) {
      extractPlaceholder.style.display = 'block';
      extractResultView.style.display = 'none';
      btnCopyRecovered.style.display = 'none';
      showToast(`Extraction Failed: ${e.message}`, 'error');
    } finally {
      btnRunExtract.disabled = false;
      btnRunExtract.innerHTML = '<span class="btn-icon">🔓</span> <span class="btn-text">Extract &amp; Decrypt Payload</span>';
    }
  });

  // =================================================================
  // Copy Recovered Text to Clipboard
  // =================================================================
  btnCopyRecovered.addEventListener('click', () => {
    const text = recoveredTextDisplay.textContent;
    if (!text) return;

    navigator.clipboard.writeText(text).then(() => {
      btnCopyRecovered.textContent = '✅ Copied!';
      showToast('Secret message copied to clipboard!', 'info');
      if (copyTimeoutId) clearTimeout(copyTimeoutId);
      copyTimeoutId = setTimeout(() => {
        btnCopyRecovered.textContent = '📋 Copy';
      }, 2000);
    }).catch(() => {
      showToast('Failed to copy to clipboard.', 'error');
    });
  });

  // =================================================================
  // Difference Map Modal Handling
  // =================================================================
  btnOpenDiffModal.addEventListener('click', () => {
    if (!lastCoverDataUrl || !lastStegoDataUrl || !lastDiffDataUrl) {
      showToast('Please embed a secret message first.', 'error');
      return;
    }

    modalCoverImg.src = lastCoverDataUrl;
    modalStegoImg.src = lastStegoDataUrl;
    modalDiffImg.src = lastDiffDataUrl;

    diffModal.classList.add('visible');
    diffModal.focus();
  });

  function closeModal() {
    diffModal.classList.remove('visible');
  }

  btnCloseDiffModal.addEventListener('click', closeModal);

  diffModal.addEventListener('click', (e) => {
    if (e.target === diffModal) {
      closeModal();
    }
  });

  // Close modal on Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && diffModal.classList.contains('visible')) {
      closeModal();
    }
  });
});
