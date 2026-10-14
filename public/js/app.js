/* Ceiba · mejoras progresivas de la interfaz (sin dependencias, compatible con la CSP estricta) */
(function () {
  'use strict';
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));

  /* Mostrar / ocultar contraseña */
  $$('[data-toggle-pw]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const input = document.getElementById(btn.dataset.togglePw);
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Ocultar' : 'Mostrar';
      btn.setAttribute('aria-label', show ? 'Ocultar contraseña' : 'Mostrar contraseña');
      input.focus();
    });
  });

  /* Medidor de fortaleza (orientativo: el servidor vuelve a validar todo) */
  const pw = $('[data-strength]');
  if (pw) {
    const meter = $('[data-meter]');
    const bar = meter.querySelector('i');
    const label = $('[data-meter-label]');
    const words = ['', 'Muy débil', 'Débil', 'Aceptable', 'Fuerte', 'Muy fuerte'];
    const update = () => {
      const v = pw.value;
      const rules = {
        len: v.length >= 10,
        case: /[a-z]/.test(v) && /[A-Z]/.test(v),
        num: /\d/.test(v),
        sym: /[^A-Za-z0-9]/.test(v),
      };
      Object.keys(rules).forEach((k) => {
        const li = $(`[data-rule="${k}"]`);
        if (li) li.classList.toggle('ok', rules[k]);
      });
      let pool = 0;
      if (/[a-z]/.test(v)) pool += 26;
      if (/[A-Z]/.test(v)) pool += 26;
      if (/\d/.test(v)) pool += 10;
      if (/[^A-Za-z0-9]/.test(v)) pool += 33;
      const bits = v.length * Math.log2(pool || 1);
      const passed = Object.values(rules).filter(Boolean).length;
      let score = !v ? 0 : passed < 4 ? Math.max(1, Math.min(2, passed - 1)) : bits < 60 ? 3 : bits < 80 ? 4 : 5;
      if (/(.)\1{3,}/.test(v)) score = Math.min(score, 2);
      meter.dataset.score = Math.min(4, Math.max(0, score - 1));
      bar.style.width = (score / 5) * 100 + '%';
      label.textContent = v ? words[score] + (passed < 4 ? ': faltan requisitos' : '') : '';
    };
    pw.addEventListener('input', update);
    update();
  }

  /* Confirmación de contraseña */
  $$('[data-match]').forEach((input) => {
    const other = document.getElementById(input.dataset.match);
    const msg = $('[data-match-msg]');
    const check = () => {
      if (!input.value) { msg.textContent = ''; input.removeAttribute('aria-invalid'); return; }
      const ok = input.value === other.value;
      msg.textContent = ok ? 'Las contraseñas coinciden.' : 'Todavía no coinciden.';
      input.setAttribute('aria-invalid', ok ? 'false' : 'true');
    };
    input.addEventListener('input', check);
    other.addEventListener('input', check);
  });

  /* Campo de código de 6 dígitos */
  $$('[data-otp]').forEach((wrap) => {
    const input = wrap.querySelector('input');
    const cells = $$('.otp-cells i', wrap);
    const form = input.form;
    let submitted = false;
    const paint = () => {
      const n = input.value.length;
      cells.forEach((c, i) => c.classList.toggle('cur', i === Math.min(n, 5)));
      wrap.classList.toggle('filled', n === 6);
    };
    input.addEventListener('input', () => {
      const clean = input.value.replace(/\D/g, '').slice(0, 6);
      if (clean !== input.value) input.value = clean;
      wrap.classList.remove('bad');
      paint();
      if (clean.length === 6 && !submitted && form) {
        submitted = true;
        setTimeout(() => (form.requestSubmit ? form.requestSubmit() : form.submit()), 120);
      }
      if (clean.length < 6) submitted = false;
    });
    input.addEventListener('focus', () => { wrap.classList.add('focus'); paint(); });
    input.addEventListener('blur', () => wrap.classList.remove('focus'));
    if ($('[data-otp-error]')) wrap.classList.add('bad');
    paint();
  });

  /* Estado de carga y protección contra doble envío */
  $$('form[data-loading]').forEach((form) => {
    form.addEventListener('submit', (e) => {
      if (form.dataset.sending) { e.preventDefault(); return; }
      form.dataset.sending = '1';
      const btn = form.querySelector('button[type=submit]');
      if (btn) { btn.classList.add('is-loading'); btn.setAttribute('aria-busy', 'true'); }
    });
  });
  window.addEventListener('pageshow', () => $$('form[data-loading]').forEach((f) => {
    delete f.dataset.sending;
    $$('.is-loading', f).forEach((b) => b.classList.remove('is-loading'));
  }));

  /* Cuenta regresiva de vencimiento del código */
  $$('[data-expires]').forEach((box) => {
    const end = parseInt(box.dataset.expires, 10);
    const out = box.querySelector('[data-countdown]');
    const tick = () => {
      const s = Math.max(0, Math.round((end - Date.now()) / 1000));
      out.textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
      if (s === 0) {
        box.classList.add('expired');
        box.firstElementChild.innerHTML = 'El código <strong>venció</strong>. Pide uno nuevo.';
        return;
      }
      setTimeout(tick, 1000);
    };
    tick();
  });

  /* Espera antes de reenviar */
  $$('[data-resend]').forEach((btn) => {
    let wait = parseInt(btn.dataset.resend, 10) || 0;
    const original = btn.textContent;
    const tick = () => {
      if (wait <= 0) { btn.disabled = false; btn.textContent = original; return; }
      btn.disabled = true;
      btn.textContent = `${original} (${wait} s)`;
      wait -= 1;
      setTimeout(tick, 1000);
    };
    tick();
  });

  /* Copiar al portapapeles */
  const copy = async (text, btn) => {
    try {
      await navigator.clipboard.writeText(text);
      const span = btn.querySelector('span') || btn;
      const prev = span.textContent;
      span.textContent = 'Copiado';
      setTimeout(() => (span.textContent = prev), 1600);
    } catch (e) { /* sin permiso de portapapeles */ }
  };
  $$('[data-copy]').forEach((btn) => btn.addEventListener('click', () => {
    copy($('[data-copy-src]', btn.parentElement).textContent.replace(/\s+/g, ''), btn);
  }));

  /* Códigos de respaldo */
  const codesList = $('[data-codes]');
  if (codesList) {
    const codes = $$('li', codesList).map((li) => li.textContent.trim());
    const cont = $('[data-continue]');
    const confirm = $('[data-confirm-saved]');
    let saved = false;
    const enable = () => {
      const ok = confirm.checked;
      cont.setAttribute('aria-disabled', ok ? 'false' : 'true');
      cont.classList.toggle('is-disabled', !ok);
    };
    cont.addEventListener('click', (e) => { if (!confirm.checked) { e.preventDefault(); confirm.focus(); } });
    confirm.addEventListener('change', enable);
    enable();
    const dl = $('[data-download-codes]');
    dl.addEventListener('click', () => {
      const text = [
        'Códigos de respaldo de Ceiba',
        `Cuenta: ${dl.dataset.account}`,
        `Generados: ${new Date().toLocaleString('es-GT')}`,
        '',
        'Cada código funciona una sola vez. Guárdalos fuera de tu computadora.',
        '',
        ...codes.map((c, i) => `${String(i + 1).padStart(2, ' ')}. ${c}`),
        '',
      ].join('\r\n');
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
      a.download = dl.dataset.filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      saved = true;
      if (saved) confirm.checked = true, enable();
    });
    $('[data-copy-codes]').addEventListener('click', (e) => copy(codes.join('\n'), e.currentTarget));
  }

  /* Confirmaciones en línea (eliminar método) */
  $$('[data-open]').forEach((btn) => btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.open);
    target.hidden = !target.hidden;
    if (!target.hidden) target.querySelector('input[type=password]').focus();
  }));

  /* Barras del gráfico de monitoreo */
  $$('[data-chart] [data-h]').forEach((b) => { b.style.height = b.dataset.h + '%'; });

  /* Bandeja de demostración: se recarga cuando llega un mensaje nuevo */
  $$('[data-reload]').forEach((b) => b.addEventListener('click', () => location.reload()));
  if ($('[data-outbox-poll]')) {
    let last = null;
    const poll = async () => {
      try {
        const r = await fetch('/demo/bandeja.json', { cache: 'no-store' });
        const j = await r.json();
        if (last !== null && j.lastId !== last) location.reload();
        last = j.lastId;
      } catch (e) { /* servidor detenido */ }
      setTimeout(poll, 2500);
    };
    poll();
  }
})();
