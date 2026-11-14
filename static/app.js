'use strict';

// 용도별 API와 화면 문구입니다. 서버의 CertificateProfile과 짝을 이룹니다.
const PURPOSES = {
    wpa3: {
        endpoint: '/api/request-cert',
        detailsTitle: '2. 기기 정보 입력',
        placeholder: '예: notebook-01',
        buttonLabel: 'Wi-Fi 인증서 발급 및 다운로드',
    },
    vpn: {
        endpoint: '/api/vpn/request-cert',
        detailsTitle: '3. 기기 정보 입력',
        placeholder: '예: vpn-notebook-01',
        buttonLabel: 'VPN 인증서 발급 및 다운로드',
    },
};

const SESSION_EXPIRED_MESSAGE = '로그인 세션이 만료되었습니다. 페이지를 새로고침한 뒤 다시 시도하세요.';

const form = document.getElementById('certificate-form');
const vpnCaStep = document.getElementById('vpn-ca-step');
const detailsStep = document.getElementById('details-step');
const detailsTitle = document.getElementById('details-title');
const commonNameInput = document.getElementById('common-name');
const passwordInput = document.getElementById('p12-password');
const confirmInput = document.getElementById('p12-password-confirm');
const issueButton = document.getElementById('issue-button');
const statusArea = document.getElementById('status');

function selectedPurpose() {
    const checked = form.querySelector('input[name="purpose"]:checked');
    return checked ? checked.value : null;
}

const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

function isFullyVisible(element) {
    const rect = element.getBoundingClientRect();
    return rect.top >= 0 && rect.bottom <= window.innerHeight;
}

// 화면 밖에 있을 때만 스크롤합니다. 이미 보이는 데스크톱에서는 화면이 움직이지 않습니다.
function bringIntoView(element, block) {
    if (!isFullyVisible(element)) {
        element.scrollIntoView({ block, behavior: prefersReducedMotion.matches ? 'auto' : 'smooth' });
    }
}

function showStatus(message, kind) {
    statusArea.textContent = message;
    statusArea.className = `status ${kind}`;
    // 결과 안내가 화면 밖에 표시되어 사용자가 놓치는 일이 없게 합니다.
    bringIntoView(statusArea, 'nearest');
}

function clearStatus() {
    statusArea.textContent = '';
    statusArea.className = 'status';
}

const passwordToggles = form.querySelectorAll('.toggle');

function setPasswordVisible(toggle, visible) {
    const input = document.getElementById(toggle.getAttribute('aria-controls'));
    input.type = visible ? 'text' : 'password';
    toggle.textContent = visible ? '숨김' : '표시';
    toggle.setAttribute('aria-label', visible ? '비밀번호 숨김' : '비밀번호 표시');
}

// 비밀번호 입력란을 비우고 가림 상태로 되돌립니다. 기기 이름은 비밀이 아니므로 남겨 둡니다.
function resetPasswordInputs() {
    passwordInput.value = '';
    confirmInput.value = '';
    passwordToggles.forEach((toggle) => setPasswordVisible(toggle, false));
}

const validatedInputs = [commonNameInput, passwordInput, confirmInput];

// 오류 문구는 해당 입력란 바로 아래에 표시하고, aria-describedby로 스크린리더에도 연결합니다.
function setFieldError(input, message) {
    const error = document.getElementById(`${input.id}-error`);
    error.textContent = message || '';
    error.hidden = !message;
    if (message) {
        input.setAttribute('aria-invalid', 'true');
    } else {
        input.removeAttribute('aria-invalid');
    }
}

function clearFieldErrors() {
    validatedInputs.forEach((input) => setFieldError(input, null));
}

// 사용자가 다시 입력하기 시작하면 그 칸의 오류 표시를 지웁니다.
validatedInputs.forEach((input) => {
    input.addEventListener('input', () => setFieldError(input, null));
});

let currentPurpose = null;

function applyPurpose(purpose) {
    const config = PURPOSES[purpose];
    // 용도가 바뀌면 다른 용도로 발급되는 실수를 막기 위해 비밀번호를 다시 입력하게 합니다.
    if (purpose !== currentPurpose) {
        resetPasswordInputs();
        clearFieldErrors();
        clearStatus();
        currentPurpose = purpose;
    }
    vpnCaStep.hidden = purpose !== 'vpn';
    detailsStep.hidden = !config;
    if (!config) {
        return;
    }
    detailsTitle.textContent = config.detailsTitle;
    commonNameInput.placeholder = config.placeholder;
    issueButton.textContent = config.buttonLabel;
}

// 주소 뒤에 #wpa3 또는 #vpn을 붙이면 해당 용도가 선택된 상태로 열립니다.
function selectPurposeFromHash() {
    const purpose = window.location.hash.slice(1);
    const radio = form.querySelector(`input[name="purpose"][value="${PURPOSES[purpose] ? purpose : ''}"]`);
    if (radio) {
        radio.checked = true;
    }
    applyPurpose(selectedPurpose());
}

form.querySelectorAll('input[name="purpose"]').forEach((radio) => {
    radio.addEventListener('change', () => {
        applyPurpose(radio.value);
        window.history.replaceState(null, '', `#${radio.value}`);
        // 새로 나타난 첫 단계가 화면 밖에 있을 때만 그 단계가 위쪽에 오도록 스크롤합니다.
        bringIntoView(vpnCaStep.hidden ? detailsStep : vpnCaStep, 'start');
    });
});
window.addEventListener('hashchange', selectPurposeFromHash);

passwordToggles.forEach((toggle) => {
    const input = document.getElementById(toggle.getAttribute('aria-controls'));
    setPasswordVisible(toggle, false);
    toggle.addEventListener('click', () => setPasswordVisible(toggle, input.type !== 'text'));
});

function commonNameError(value) {
    if (value.length === 0) {
        return '기기 이름을 입력하세요.';
    }
    if (value.length > 253 || !/^[A-Za-z0-9.-]+$/.test(value)) {
        return '영문자, 숫자, 점, 하이픈만 쓸 수 있습니다.';
    }
    const labelsAreValid = value.split('.').every((label) =>
        label.length >= 1 && label.length <= 63 && !label.startsWith('-') && !label.endsWith('-'));
    return labelsAreValid ? null : '점이나 하이픈으로 시작하거나 끝날 수 없고, 점을 연달아 쓸 수 없습니다.';
}

function passwordError(value) {
    const length = [...value].length;
    if (length < 8 || length > 128) {
        return '8~128자로 입력하세요.';
    }
    return /[\r\n\0]/.test(value) ? '줄바꿈 문자는 쓸 수 없습니다.' : null;
}

// 서버와 같은 규칙을 먼저 확인해, 잘못된 입력으로 요청이 나가지 않게 합니다.
// 잘못된 칸 모두에 문구를 표시하고, 잘못된 입력란 목록을 돌려줍니다.
function validateInputs() {
    const errors = [
        [commonNameInput, commonNameError(commonNameInput.value.trim())],
        [passwordInput, passwordError(passwordInput.value)],
        [confirmInput, passwordInput.value === confirmInput.value ? null : '비밀번호가 일치하지 않습니다.'],
    ];
    errors.forEach(([input, message]) => setFieldError(input, message));
    return errors.filter(([, message]) => message).map(([input]) => input);
}

function filenameFrom(response, fallback) {
    const disposition = response.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="([^"]+)"/);
    return match ? match[1] : fallback;
}

async function serverMessage(response) {
    const contentType = response.headers.get('Content-Type') || '';
    if (!contentType.startsWith('text/plain')) {
        return null;
    }
    const text = (await response.text()).trim();
    return text.length > 0 && text.length <= 300 ? text : null;
}

// 상태 코드별로 정해진 안내를 보여줍니다. 서버가 보낸 문구는 서버가 만든 일반 텍스트일 때만 씁니다.
async function failureMessage(response) {
    if (response.type === 'opaqueredirect' || response.status === 401) {
        return SESSION_EXPIRED_MESSAGE;
    }
    const message = await serverMessage(response);
    switch (response.status) {
    case 400:
        return message || '입력값을 확인하세요.';
    case 502:
        return message || 'CA가 인증서 발급을 거부했습니다. 관리자에게 문의하세요.';
    case 503:
        return message || '다른 발급 요청이 처리 중입니다. 잠시 후 다시 시도하세요.';
    case 504:
        return message || 'CA 응답이 늦어 발급하지 못했습니다. 잠시 후 다시 시도하세요.';
    default:
        return message || `발급에 실패했습니다. (HTTP ${response.status})`;
    }
}

function download(blob, filename) {
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => window.URL.revokeObjectURL(url), 1000);
}

form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const purpose = selectedPurpose();
    const config = PURPOSES[purpose];
    if (!config) {
        showStatus('먼저 인증서를 사용할 네트워크를 선택하세요.', 'error');
        return;
    }
    const invalidInputs = validateInputs();
    if (invalidInputs.length > 0) {
        clearStatus();
        // 첫 번째 잘못된 칸으로 이동하면 스크린리더가 그 칸의 오류 문구를 함께 읽습니다.
        invalidInputs[0].focus();
        return;
    }

    const commonName = commonNameInput.value.trim();
    showStatus('CA에 인증서 발급을 요청하는 중입니다…', 'pending');
    issueButton.disabled = true;

    try {
        const response = await fetch(config.endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ common_name: commonName, p12_password: passwordInput.value }),
            // 세션이 만료되면 Cloudflare Access가 로그인 페이지로 리다이렉트합니다.
            // 따라가면 CORS 오류로만 보이므로 직접 감지합니다.
            redirect: 'manual',
        });

        if (!response.ok) {
            showStatus(await failureMessage(response), 'error');
            return;
        }

        const fallbackName = purpose === 'vpn' ? `vpn-${commonName}.pfx` : `${commonName}.pfx`;
        download(await response.blob(), filenameFrom(response, fallbackName));
        resetPasswordInputs();
        showStatus('발급이 끝나 PFX 다운로드를 시작했습니다. 방금 입력한 비밀번호로 설치하고, 설치가 끝나면 다운로드한 파일을 지우세요.', 'success');
    } catch {
        showStatus('서버에 연결하지 못했습니다. 네트워크 상태를 확인하고 다시 시도하세요.', 'error');
    } finally {
        issueButton.disabled = false;
    }
});

selectPurposeFromHash();
