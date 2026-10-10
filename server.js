'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const VERSION = '1.0.0';
const GRADLE_VERSION = '8.9';

const PORT = Number(process.env.PORT || 8080);
const AUTH_TOKEN = process.env.WORKER_AUTH_TOKEN || '';
const DATA_DIR = process.env.WORKER_DATA_DIR || '/var/lib/androidbuildworker';
const SDK_ROOT = process.env.ANDROID_SDK_ROOT || process.env.ANDROID_HOME || '';
const JAVA_HOME = process.env.JAVA_HOME || '';
const GRADLE_BIN = process.env.GRADLE_BIN || 'gradle';
const KEY_ALIAS = process.env.KEY_ALIAS || 'release';
const PUBLIC_URL = trimSlashes(process.env.WORKER_PUBLIC_URL || '');
const MAX_CONCURRENT = Math.max(1, Number(process.env.MAX_CONCURRENT_BUILDS || 1));
const MAX_QUEUE = Math.max(1, Number(process.env.MAX_QUEUE_SIZE || 10));
const BUILD_TIMEOUT_MS = Math.max(60000, Number(process.env.BUILD_TIMEOUT_MS || 1500000));
const RETENTION_HOURS = Math.max(1, Number(process.env.BUILD_RETENTION_HOURS || 72));
const MAX_SOURCE_BYTES = Math.max(1048576, Number(process.env.MAX_SOURCE_BYTES || 62914560));
const REQUEST_LIMIT_BYTES = 262144;
const RATE_LIMIT_PER_MINUTE = Math.max(20, Number(process.env.RATE_LIMIT_PER_MINUTE || 180));

const BUILD_ROOT = path.join(DATA_DIR, 'builds');
const GRADLE_HOME = path.join(DATA_DIR, 'gradle-home');
const KEY_DIR = path.join(DATA_DIR, 'keys');
const KEYSTORE_PATH = path.join(KEY_DIR, 'release.jks');
const KEYSTORE_SECRET = path.join(KEY_DIR, 'release.secret');

const STAGE_DEFS = {
  queued: { label: 'QUEUED', progress: 2, indeterminate: false },
  creating_project: { label: 'CREATING PROJECT', progress: 12, indeterminate: false },
  configuring_android: { label: 'CONFIGURING ANDROID', progress: 28, indeterminate: false },
  processing_icon: { label: 'PROCESSING ICON', progress: 40, indeterminate: false },
  compiling: { label: 'COMPILING', progress: null, indeterminate: true },
  signing: { label: 'SIGNING', progress: 84, indeterminate: false },
  verifying: { label: 'VERIFYING APK', progress: 92, indeterminate: false },
  ready: { label: 'APK READY', progress: 100, indeterminate: false },
  failed: { label: 'BUILD FAILED', progress: null, indeterminate: false },
  cancelled: { label: 'CANCELLED', progress: null, indeterminate: false }
};

const jobs = new Map();
const queue = [];
const rateBuckets = new Map();
let activeBuilds = 0;
let toolCache = { at: 0, value: null };

function trimSlashes(value) {
  let out = String(value || '');
  while (out.endsWith('/')) out = out.slice(0, -1);
  return out;
}

function sanitizeName(value) {
  const cleaned = String(value == null ? 'app' : value).toLowerCase().replace(/[^a-z0-9._-]/g, '-');
  let out = '';
  for (let i = 0; i < cleaned.length; i += 1) {
    const ch = cleaned.charAt(i);
    out += (ch === '-' && (i === 0 || cleaned.charAt(i - 1) === '-')) ? '' : ch;
  }
  while (out.startsWith('-') || out.startsWith('.')) out = out.slice(1);
  while (out.endsWith('-') || out.endsWith('.')) out = out.slice(0, -1);
  return out || 'app';
}

function isValidPackageName(value) {
  const text = String(value || '');
  if (text.length < 4 || text.length > 120) return false;
  const segments = text.split('.');
  if (segments.length < 2) return false;
  for (let i = 0; i < segments.length; i += 1) {
    if (!/^[a-zA-Z][a-zA-Z0-9_]{0,60}$/.test(segments[i])) return false;
  }
  return true;
}

function tail(text, length) {
  const value = String(text || '');
  return value.length <= length ? value : value.slice(value.length - length);
}

function redact(text) {
  let value = String(text == null ? '' : text);
  if (keySecretPassword()) value = value.split(keySecretPassword()).join('***');
  if (AUTH_TOKEN) value = value.split(AUTH_TOKEN).join('***');
  return value;
}

function keySecretPassword() {
  try {
    return fs.readFileSync(KEYSTORE_SECRET, 'utf8').trim();
  } catch (error) {
    return process.env.KEYSTORE_PASSWORD || '';
  }
}

function buildEnv() {
  const env = Object.assign({}, process.env);
  env.GRADLE_USER_HOME = GRADLE_HOME;
  if (SDK_ROOT) {
    env.ANDROID_SDK_ROOT = SDK_ROOT;
    env.ANDROID_HOME = SDK_ROOT;
  }
  if (JAVA_HOME) env.JAVA_HOME = JAVA_HOME;
  return env;
}

function logLine(job, message) {
  const line = new Date().toISOString() + '  ' + redact(message);
  job.log.push(line);
  if (job.log.length > 240) job.log.splice(0, job.log.length - 240);
  process.stdout.write('[' + job.buildId + '] ' + redact(message) + os.EOL);
}

function persist(job) {
  try {
    fs.mkdirSync(job.dir, { recursive: true });
    fs.writeFileSync(path.join(job.dir, 'status.json'), JSON.stringify(publicJob(job), null, 2));
  } catch (error) {
    process.stderr.write('Could not persist build state: ' + error.message + os.EOL);
  }
}

function setStage(job, key) {
  const def = STAGE_DEFS[key] || STAGE_DEFS.queued;
  job.stage = key;
  job.stageLabel = def.label;
  job.progress = def.progress;
  job.indeterminate = def.indeterminate;
  job.stageHistory = (job.stageHistory || []).concat([{ stage: key, label: def.label, at: new Date().toISOString() }]);
  persist(job);
}

function downloadToken(buildId, artifact) {
  return crypto.createHmac('sha256', AUTH_TOKEN || 'worker').update(buildId + ':' + artifact).digest('hex').slice(0, 40);
}

function publicBaseUrl(req) {
  if (PUBLIC_URL) return PUBLIC_URL;
  const forwarded = req && req.headers['x-forwarded-proto'] ? String(req.headers['x-forwarded-proto']).split(',')[0].trim() : '';
  const protocol = forwarded || (req && req.socket && req.socket.encrypted ? 'https' : 'http');
  const host = req && req.headers.host ? req.headers.host : 'localhost:' + PORT;
  return protocol + '://' + host;
}

function artifactUrl(job, artifact, base) {
  return base + '/build/' + job.buildId + '/' + artifact + '?token=' + downloadToken(job.buildId, artifact);
}

function publicJob(job, base) {
  const root = base || PUBLIC_URL || '';
  const artifacts = {};
  const order = ['apk', 'aab', 'source'];
  for (let i = 0; i < order.length; i += 1) {
    const key = order[i];
    const item = job.artifacts ? job.artifacts[key] : null;
    if (!item) continue;
    artifacts[key] = {
      size: item.size,
      sha256: item.sha256 || null,
      verified: item.verified === true,
      signed: item.signed === true,
      url: root ? artifactUrl(job, key, root) : null
    };
  }
  return {
    buildId: job.buildId,
    status: job.status,
    stage: job.stage,
    stageLabel: job.stageLabel || (STAGE_DEFS[job.stage] || STAGE_DEFS.queued).label,
    progress: job.progress,
    indeterminate: job.indeterminate === true,
    queuePosition: job.queuePosition || 0,
    createdAt: job.createdAt,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    durationMs: job.startedAt && job.finishedAt ? job.finishedAt - job.startedAt : null,
    error: job.error,
    warnings: job.warnings || [],
    logTail: (job.log || []).slice(-25).join(os.EOL),
    verification: job.verification || null,
    stages: (job.stageHistory || []).map(function (entry) { return { stage: entry.stage, label: entry.label, at: entry.at }; }),
    artifacts: artifacts
  };
}

function runCommand(command, args, options) {
  const opts = options || {};
  return new Promise(function (resolve, reject) {
    let child;
    try {
      child = spawn(command, args, { cwd: opts.cwd, env: buildEnv(), stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (error) {
      reject(new Error(command + ' could not start: ' + error.message));
      return;
    }
    if (opts.onChild) opts.onChild(child);
    let output = '';
    const cap = 400000;
    function collect(chunk) {
      if (output.length < cap) output += chunk.toString();
    }
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    let timer = null;
    if (opts.timeout) {
      timer = setTimeout(function () {
        output += os.EOL + 'Command timed out after ' + Math.round(opts.timeout / 1000) + ' seconds';
        try { child.kill('SIGKILL'); } catch (error) { /* already gone */ }
      }, opts.timeout);
    }
    child.on('error', function (error) {
      if (timer) clearTimeout(timer);
      reject(new Error(command + ' could not run: ' + error.message));
    });
    child.on('close', function (code) {
      if (timer) clearTimeout(timer);
      if (code === 0) resolve(output);
      else reject(new Error(command + ' exited with code ' + code + os.EOL + tail(redact(output), 4000)));
    });
  });
}

function downloadFile(url, target, maxBytes) {
  return new Promise(function (resolve, reject) {
    const isHttps = url.indexOf('https://') === 0;
    if (!isHttps && url.indexOf('http://') !== 0) {
      reject(new Error('The source package URL must be http or https'));
      return;
    }
    const client = isHttps ? https : http;
    const request = client.get(url, { headers: { 'User-Agent': 'android-build-worker/' + VERSION } }, function (response) {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        downloadFile(response.headers.location, target, maxBytes).then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error('Source package download failed with HTTP ' + response.statusCode));
        return;
      }
      const declared = Number(response.headers['content-length'] || 0);
      if (declared && declared > maxBytes) {
        response.resume();
        reject(new Error('The source package is larger than the allowed limit'));
        return;
      }
      const stream = fs.createWriteStream(target);
      let received = 0;
      let settled = false;
      response.on('data', function (chunk) {
        received += chunk.length;
        if (received > maxBytes && !settled) {
          settled = true;
          response.destroy();
          stream.destroy();
          reject(new Error('The source package exceeded the allowed size'));
        }
      });
      response.pipe(stream);
      stream.on('finish', function () {
        if (!settled) {
          settled = true;
          resolve(received);
        }
      });
      stream.on('error', function (error) {
        if (!settled) {
          settled = true;
          reject(error);
        }
      });
    });
    request.on('error', reject);
    request.setTimeout(120000, function () {
      request.destroy(new Error('Source package download timed out'));
    });
  });
}

function sha256File(file) {
  return new Promise(function (resolve, reject) {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(file);
    stream.on('data', function (chunk) { hash.update(chunk); });
    stream.on('end', function () { resolve(hash.digest('hex')); });
    stream.on('error', reject);
  });
}

function sdkBuildTools() {
  try {
    const dirs = fs.readdirSync(path.join(SDK_ROOT, 'build-tools')).sort();
    if (!dirs.length) return '';
    return path.join(SDK_ROOT, 'build-tools', dirs[dirs.length - 1]);
  } catch (error) {
    return '';
  }
}

function toolPaths() {
  const buildTools = sdkBuildTools();
  const javaBin = JAVA_HOME ? path.join(JAVA_HOME, 'bin') : '';
  return {
    buildTools: buildTools,
    zipalign: buildTools ? path.join(buildTools, 'zipalign') : 'zipalign',
    apksigner: buildTools ? path.join(buildTools, 'apksigner') : 'apksigner',
    aapt: buildTools ? path.join(buildTools, 'aapt') : 'aapt',
    keytool: javaBin && fs.existsSync(path.join(javaBin, 'keytool')) ? path.join(javaBin, 'keytool') : 'keytool',
    jarsigner: javaBin && fs.existsSync(path.join(javaBin, 'jarsigner')) ? path.join(javaBin, 'jarsigner') : 'jarsigner'
  };
}

function ensureKeystore() {
  fs.mkdirSync(KEY_DIR, { recursive: true });
  const tools = toolPaths();
  let password = process.env.KEYSTORE_PASSWORD || '';
  if (!fs.existsSync(KEYSTORE_PATH)) {
    if (!password) password = crypto.randomBytes(24).toString('hex');
    const result = require('child_process').spawnSync(tools.keytool, [
      '-genkeypair',
      '-keystore', KEYSTORE_PATH,
      '-alias', KEY_ALIAS,
      '-keyalg', 'RSA',
      '-keysize', '2048',
      '-validity', '10950',
      '-storepass', password,
      '-keypass', password,
      '-dname', 'CN=Android App Builder, OU=Release, O=Generated Apps, L=NA, ST=NA, C=NA'
    ], { env: buildEnv() });
    if (result.status !== 0) {
      throw new Error('Could not generate the release keystore: ' + tail(redact(result.stderr ? result.stderr.toString() : ''), 800));
    }
    fs.writeFileSync(KEYSTORE_SECRET, password, { mode: 0o600 });
  } else if (!password) {
    password = keySecretPassword();
  }
  if (!password) throw new Error('The release keystore is present but its password could not be read');
  return { path: KEYSTORE_PATH, password: password };
}

function readBadging(badgingOutput) {
  const result = { packageName: '', versionCode: '', versionName: '', label: '' };
  const lines = String(badgingOutput || '').split(os.EOL);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.indexOf('package:') === 0) {
      result.packageName = between(line, "name='", "'");
      result.versionCode = between(line, "versionCode='", "'");
      result.versionName = between(line, "versionName='", "'");
    }
    if (line.indexOf('application-label:') === 0) result.label = between(line, "application-label:'", "'");
  }
  return result;
}

function between(text, start, end) {
  const from = text.indexOf(start);
  if (from < 0) return '';
  const rest = text.slice(from + start.length);
  const to = rest.indexOf(end);
  return to < 0 ? rest : rest.slice(0, to);
}

function parseSigner(output) {
  const lines = String(output || '').split(os.EOL);
  for (let i = 0; i < lines.length; i += 1) {
    if (lines[i].indexOf('SHA-256 digest:') >= 0) {
      return between(lines[i], 'SHA-256 digest:', ' ').trim() || lines[i].trim();
    }
  }
  for (let i = 0; i < lines.length; i += 1) {
    if (lines[i].indexOf('Signer #1 certificate DN:') >= 0) {
      return between(lines[i], 'certificate DN:', ' ').trim();
    }
  }
  return '';
}

function verifyProjectFiles(projectDir) {
  const required = [
    'settings.gradle',
    'build.gradle',
    'gradle.properties',
    'app/build.gradle',
    'app/src/main/AndroidManifest.xml'
  ];
  for (let i = 0; i < required.length; i += 1) {
    if (!fs.existsSync(path.join(projectDir, required[i]))) {
      throw new Error('The source package is missing ' + required[i]);
    }
  }
}

function writeLocalProperties(projectDir) {
  if (!SDK_ROOT) return;
  fs.writeFileSync(path.join(projectDir, 'local.properties'), 'sdk.dir=' + SDK_ROOT + os.EOL);
}

function verifyIcons(projectDir, job) {
  const resDir = path.join(projectDir, 'app', 'src', 'main', 'res');
  let found = 0;
  const folders = fs.existsSync(resDir) ? fs.readdirSync(resDir) : [];
  for (let i = 0; i < folders.length; i += 1) {
    if (folders[i].indexOf('mipmap') !== 0) continue;
    const files = fs.readdirSync(path.join(resDir, folders[i]));
    for (let k = 0; k < files.length; k += 1) {
      const file = path.join(resDir, folders[i], files[k]);
      const handle = fs.openSync(file, 'r');
      const header = Buffer.alloc(8);
      fs.readSync(handle, header, 0, 8, 0);
      fs.closeSync(handle);
      const isPng = header[0] === 0x89 && header[1] === 0x50;
      const isJpg = header[0] === 0xff && header[1] === 0xd8;
      const isWebp = header.toString('ascii', 0, 4) === 'RIFF';
      if (isPng || isJpg || isWebp) found += 1;
    }
  }
  if (found === 0) throw new Error('No valid launcher icon was found in the generated project');
  logLine(job, 'Validated ' + found + ' launcher icon file(s)');
}

function findArtifact(dir, suffix) {
  if (!fs.existsSync(dir)) return '';
  const files = fs.readdirSync(dir);
  for (let i = 0; i < files.length; i += 1) {
    if (suffix && files[i].endsWith(suffix)) return path.join(dir, files[i]);
  }
  return '';
}

async function runBuild(job) {
  const tools = toolPaths();
  const config = job.config;
  job.startedAt = Date.now();
  job.status = 'building';
  job.queuePosition = 0;
  persist(job);

  try {
    if (job.cancelled) throw new Error('Build cancelled');

    setStage(job, 'creating_project');
    const zipPath = path.join(job.dir, 'source.zip');
    const bytes = await downloadFile(config.sourceZipUrl, zipPath, MAX_SOURCE_BYTES);
    logLine(job, 'Downloaded source package (' + Math.round(bytes / 1024) + ' KB)');
    const projectDir = path.join(job.dir, 'project');
    fs.mkdirSync(projectDir, { recursive: true });
    await runCommand('unzip', ['-q', '-o', zipPath, '-d', projectDir]);
    verifyProjectFiles(projectDir);
    writeLocalProperties(projectDir);

    if (job.cancelled) throw new Error('Build cancelled');

    setStage(job, 'configuring_android');
    await runCommand(GRADLE_BIN, ['wrapper', '--gradle-version', GRADLE_VERSION, '--distribution-type', 'bin', '--no-daemon'], { cwd: projectDir, timeout: 300000 });
    const gradlew = path.join(projectDir, 'gradlew');
    if (!fs.existsSync(gradlew)) throw new Error('The Gradle wrapper could not be generated');
    logLine(job, 'Gradle wrapper ready (Gradle ' + GRADLE_VERSION + ')');

    const sourceOut = path.join(job.dir, 'source-project.zip');
    await runCommand('zip', ['-r', '-q', sourceOut, '.',
      '-x', 'local.properties',
      '-x', '*.jks', '-x', '*.keystore', '-x', '*.pepk', '-x', '*.secret',
      '-x', '.gradle/*', '-x', 'build/*', '-x', 'app/build/*', '-x', 'gradle/wrapper/gradle-wrapper.jar.orig'
    ], { cwd: projectDir });
    job.artifacts.source = { size: fs.statSync(sourceOut).size, verified: true, signed: false };
    logLine(job, 'Source package rebuilt with the Gradle wrapper');

    if (job.cancelled) throw new Error('Build cancelled');

    setStage(job, 'processing_icon');
    verifyIcons(projectDir, job);

    const keystore = ensureKeystore();

    if (job.cancelled) throw new Error('Build cancelled');

    setStage(job, 'compiling');
    const gradleOutput = await runCommand(gradlew, ['assembleRelease', '--no-daemon', '--stacktrace'], {
      cwd: projectDir,
      timeout: BUILD_TIMEOUT_MS,
      onChild: function (child) { job.child = child; }
    });
    logLine(job, tail(redact(gradleOutput), 1200));

    const apkDir = path.join(projectDir, 'app', 'build', 'outputs', 'apk', 'release');
    let apkPath = findArtifact(apkDir, '-release-unsigned.apk');
    if (!apkPath) apkPath = findArtifact(apkDir, '-release.apk');
    if (!apkPath) apkPath = findArtifact(apkDir, '.apk');
    if (!apkPath) throw new Error('Gradle finished but no APK was produced in app/build/outputs/apk/release');
    logLine(job, 'Gradle produced ' + path.basename(apkPath));

    let aabPath = '';
    if (config.buildType === 'aab' || config.buildType === 'both') {
      try {
        await runCommand(gradlew, ['bundleRelease', '--no-daemon'], { cwd: projectDir, timeout: BUILD_TIMEOUT_MS, onChild: function (child) { job.child = child; } });
        aabPath = findArtifact(path.join(projectDir, 'app', 'build', 'outputs', 'bundle', 'release'), '.aab');
        if (!aabPath) throw new Error('Gradle finished but no app bundle was produced');
        logLine(job, 'Gradle produced ' + path.basename(aabPath));
      } catch (bundleError) {
        if (config.buildType === 'aab') throw bundleError;
        job.warnings = (job.warnings || []).concat(['App bundle step failed: ' + tail(redact(bundleError.message), 600)]);
        logLine(job, 'App bundle step failed, continuing with the APK');
      }
    }

    if (job.cancelled) throw new Error('Build cancelled');

    setStage(job, 'signing');
    const alignedApk = path.join(apkDir, 'app-release-aligned.apk');
    const finalApk = path.join(apkDir, 'app-release.apk');
    if (apkPath.endsWith('-unsigned.apk') || apkPath.indexOf('unsigned') >= 0) {
      await runCommand(tools.zipalign, ['-f', '-p', '4', apkPath, alignedApk]);
      await runCommand(tools.apksigner, ['sign',
        '--ks', keystore.path,
        '--ks-key-alias', KEY_ALIAS,
        '--ks-pass', 'pass:' + keystore.password,
        '--key-pass', 'pass:' + keystore.password,
        '--out', finalApk,
        alignedApk
      ]);
      try { fs.unlinkSync(alignedApk); } catch (error) { /* not present */ }
      logLine(job, 'APK zipaligned and signed with the release keystore');
    } else if (apkPath !== finalApk) {
      fs.copyFileSync(apkPath, finalApk);
      logLine(job, 'Using the APK produced by Gradle');
    }

    setStage(job, 'verifying');
    if (!fs.existsSync(finalApk)) throw new Error('The signed APK was not created');
    const stat = fs.statSync(finalApk);
    if (!stat.size) throw new Error('The signed APK is empty');

    const listing = await runCommand('unzip', ['-l', finalApk]);
    const hasManifest = listing.indexOf('AndroidManifest.xml') >= 0;
    const hasDex = listing.indexOf('classes.dex') >= 0;
    if (!hasManifest) throw new Error('Verification failed: the APK contains no AndroidManifest.xml');
    if (!hasDex) throw new Error('Verification failed: the APK contains no classes.dex');

    const signerOutput = await runCommand(tools.apksigner, ['verify', '--print-certs', '--verbose', finalApk]);
    if (signerOutput.indexOf('DOES NOT VERIFY') >= 0 || signerOutput.indexOf('ERROR:') >= 0) {
      throw new Error('Verification failed: the release signature is not valid');
    }

    let badging = null;
    try {
      const badgingOutput = await runCommand(tools.aapt, ['dump', 'badging', finalApk]);
      badging = readBadging(badgingOutput);
      if (badging.packageName && badging.packageName !== config.packageName) {
        throw new Error('The APK declares package ' + badging.packageName + ' instead of ' + config.packageName);
      }
      if (badging.versionCode && Number(badging.versionCode) !== Number(config.versionCode)) {
        throw new Error('The APK declares version code ' + badging.versionCode + ' instead of ' + config.versionCode);
      }
      if (badging.versionName && badging.versionName !== config.versionName) {
        throw new Error('The APK declares version name ' + badging.versionName + ' instead of ' + config.versionName);
      }
    } catch (badgingError) {
      if (badgingError.message.indexOf('The APK declares') === 0) throw badgingError;
      job.warnings = (job.warnings || []).concat(['Android asset check unavailable: ' + tail(badgingError.message, 300)]);
    }

    const sha256 = await sha256File(finalApk);
    job.verification = {
      apkSigned: true,
      manifestPresent: hasManifest,
      dexPresent: hasDex,
      packageName: badging && badging.packageName ? badging.packageName : config.packageName,
      versionCode: badging && badging.versionCode ? Number(badging.versionCode) : config.versionCode,
      versionName: badging && badging.versionName ? badging.versionName : config.versionName,
      label: badging && badging.label ? badging.label : config.appName,
      sha256: sha256
    };
    job.artifacts.apk = {
      size: stat.size,
      sha256: sha256,
      verified: true,
      signed: true,
      signer: parseSigner(signerOutput)
    };

    if (aabPath) {
      try {
        await runCommand(tools.jarsigner, ['-keystore', keystore.path, '-storepass', keystore.password, '-keypass', keystore.password, aabPath, KEY_ALIAS]);
        const aabStat = fs.statSync(aabPath);
        job.artifacts.aab = { size: aabStat.size, sha256: await sha256File(aabPath), verified: true, signed: true };
        logLine(job, 'App bundle signed');
      } catch (signError) {
        job.warnings = (job.warnings || []).concat(['App bundle signing failed: ' + tail(redact(signError.message), 400)]);
        job.artifacts.aab = { size: fs.statSync(aabPath).size, sha256: await sha256File(aabPath), verified: true, signed: false };
      }
    }

    job.status = 'ready';
    job.finishedAt = Date.now();
    setStage(job, 'ready');
    logLine(job, 'Build complete: verified APK ' + Math.round(stat.size / 1024) + ' KB');
    persist(job);
  } catch (error) {
    job.error = redact(error && error.message ? error.message : String(error));
    job.status = job.cancelled ? 'cancelled' : 'failed';
    job.finishedAt = Date.now();
    setStage(job, job.cancelled ? 'cancelled' : 'failed');
    logLine(job, 'Build failed: ' + job.error);
    persist(job);
  } finally {
    job.child = null;
  }
}

function pump() {
  while (activeBuilds < MAX_CONCURRENT && queue.length) {
    const id = queue.shift();
    const job = jobs.get(id);
    if (!job) continue;
    if (job.cancelled) {
      job.status = 'cancelled';
      setStage(job, 'cancelled');
      continue;
    }
    activeBuilds += 1;
    runBuild(job).finally(function () {
      activeBuilds -= 1;
      pump();
    });
  }
  queue.forEach(function (id, index) {
    const job = jobs.get(id);
    if (job) {
      job.queuePosition = index + 1;
      persist(job);
    }
  });
}

function enqueue(payload) {
  if (queue.length >= MAX_QUEUE) {
    const error = new Error('The build queue is full. Try again shortly.');
    error.statusCode = 503;
    throw error;
  }
  const config = sanitizeConfig(payload);
  const buildId = String(payload.buildId || crypto.randomUUID());
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(buildId)) throw new Error('Invalid build id');
  const dir = path.join(BUILD_ROOT, buildId);
  fs.mkdirSync(dir, { recursive: true });
  const job = {
    buildId: buildId,
    dir: dir,
    status: 'queued',
    stage: 'queued',
    stageLabel: STAGE_DEFS.queued.label,
    progress: STAGE_DEFS.queued.progress,
    indeterminate: false,
    queuePosition: queue.length + 1,
    createdAt: Date.now(),
    startedAt: null,
    finishedAt: null,
    error: null,
    cancelled: false,
    warnings: [],
    log: [],
    stageHistory: [{ stage: 'queued', label: STAGE_DEFS.queued.label, at: new Date().toISOString() }],
    artifacts: {},
    config: config,
    child: null
  };
  jobs.set(buildId, job);
  persist(job);
  queue.push(buildId);
  setImmediate(pump);
  return job;
}

function sanitizeConfig(payload) {
  const source = payload && typeof payload === 'object' ? payload : {};
  const packageName = String(source.packageName || '');
  if (!isValidPackageName(packageName)) throw new Error('Invalid Android package name');
  const sourceZipUrl = String(source.sourceZipUrl || '');
  if (sourceZipUrl.indexOf('https://') !== 0 && sourceZipUrl.indexOf('http://') !== 0) {
    throw new Error('A source package URL is required');
  }
  const versionCode = Number(source.versionCode || 1);
  if (!Number.isInteger(versionCode) || versionCode < 1 || versionCode > 2100000000) {
    throw new Error('Invalid version code');
  }
  const versionName = String(source.versionName || '1.0').slice(0, 40);
  const buildType = ['apk', 'aab', 'both'].indexOf(source.buildType) >= 0 ? source.buildType : 'apk';
  return {
    appName: String(source.appName || 'Android App').slice(0, 80),
    packageName: packageName,
    websiteUrl: String(source.websiteUrl || '').slice(0, 500),
    versionName: versionName,
    versionCode: versionCode,
    buildType: buildType,
    sourceZipUrl: sourceZipUrl
  };
}

function loadJobs() {
  fs.mkdirSync(BUILD_ROOT, { recursive: true });
  const dirs = fs.readdirSync(BUILD_ROOT);
  for (let i = 0; i < dirs.length; i += 1) {
    const dir = path.join(BUILD_ROOT, dirs[i]);
    const statusFile = path.join(dir, 'status.json');
    if (!fs.existsSync(statusFile)) continue;
    try {
      const saved = JSON.parse(fs.readFileSync(statusFile, 'utf8'));
      const job = {
        buildId: saved.buildId,
        dir: dir,
        status: saved.status,
        stage: saved.stage,
        stageLabel: saved.stageLabel,
        progress: saved.progress,
        indeterminate: false,
        queuePosition: 0,
        createdAt: saved.createdAt,
        startedAt: saved.startedAt,
        finishedAt: saved.finishedAt,
        error: saved.error,
        cancelled: false,
        warnings: saved.warnings || [],
        log: String(saved.logTail || '').split(os.EOL),
        stageHistory: saved.stages || [],
        verification: saved.verification || null,
        artifacts: {},
        config: null,
        child: null
      };
      const order = ['apk', 'aab', 'source'];
      for (let k = 0; k < order.length; k += 1) {
        const key = order[k];
        const item = saved.artifacts ? saved.artifacts[key] : null;
        if (item) job.artifacts[key] = { size: item.size, sha256: item.sha256, verified: item.verified, signed: item.signed };
      }
      if (job.status === 'building' || job.status === 'queued') {
        job.status = 'failed';
        job.stage = 'failed';
        job.stageLabel = STAGE_DEFS.failed.label;
        job.error = 'The worker restarted while this build was running. Please build again.';
      }
      jobs.set(job.buildId, job);
    } catch (error) {
      process.stderr.write('Could not restore build ' + dirs[i] + ': ' + error.message + os.EOL);
    }
  }
}

function artifactFile(job, artifact) {
  if (artifact === 'apk') {
    const file = path.join(job.dir, 'project', 'app', 'build', 'outputs', 'apk', 'release', 'app-release.apk');
    return fs.existsSync(file) ? { file: file, type: 'application/vnd.android.package-archive', name: sanitizeName(job.config ? job.config.appName : 'app') + '-release.apk' } : null;
  }
  if (artifact === 'aab') {
    const file = path.join(job.dir, 'project', 'app', 'build', 'outputs', 'bundle', 'release', 'app-release.aab');
    return fs.existsSync(file) ? { file: file, type: 'application/octet-stream', name: sanitizeName(job.config ? job.config.appName : 'app') + '-release.aab' } : null;
  }
  if (artifact === 'source') {
    const file = path.join(job.dir, 'source-project.zip');
    const fallback = path.join(job.dir, 'source.zip');
    if (fs.existsSync(file)) return { file: file, type: 'application/zip', name: sanitizeName(job.config ? job.config.appName : 'app') + '-android-source.zip' };
    if (fs.existsSync(fallback)) return { file: fallback, type: 'application/zip', name: sanitizeName(job.config ? job.config.appName : 'app') + '-android-source.zip' };
    return null;
  }
  return null;
}

function checkHealth() {
  const now = Date.now();
  if (toolCache.value && now - toolCache.at < 60000) return toolCache.value;
  const tools = toolPaths();
  const sdkOk = Boolean(SDK_ROOT && fs.existsSync(SDK_ROOT));
  let platforms = [];
  let buildTools = [];
  try { platforms = fs.readdirSync(path.join(SDK_ROOT, 'platforms')); } catch (error) { platforms = []; }
  try { buildTools = fs.readdirSync(path.join(SDK_ROOT, 'build-tools')); } catch (error) { buildTools = []; }

  const result = {
    service: 'android-build-worker',
    version: VERSION,
    status: sdkOk && platforms.length > 0 && buildTools.length > 0 ? 'ok' : 'degraded',
    androidSdk: sdkOk,
    java: Boolean(JAVA_HOME && fs.existsSync(path.join(JAVA_HOME, 'bin', 'java'))),
    gradle: false,
    javaVersion: process.env.JAVA_VERSION || '',
    gradleVersion: GRADLE_VERSION,
    sdkPath: SDK_ROOT,
    sdkPlatforms: platforms,
    buildTools: buildTools,
    diskFreeGb: 0,
    queueSize: jobs.size ? Array.from(jobs.values()).filter(function (job) { return job.status === 'queued'; }).length : 0,
    currentBuilds: activeBuilds,
    maxConcurrentBuilds: MAX_CONCURRENT,
    retentionHours: RETENTION_HOURS,
    uptimeSeconds: Math.round(process.uptime()),
    time: new Date().toISOString()
  };

  try {
    const stats = fs.statfsSync(DATA_DIR);
    result.diskFreeGb = Math.round((stats.bavail * stats.bsize) / 1073741824 * 10) / 10;
  } catch (error) {
    result.diskFreeGb = 0;
  }

  try {
    const sync = require('child_process').spawnSync('gradle', ['--version'], { env: buildEnv(), timeout: 20000 });
    const text = String(sync.stdout || '') + String(sync.stderr || '');
    result.gradle = sync.status === 0;
    const versionLine = text.split(os.EOL).filter(function (line) { return line.indexOf('Gradle ') === 0; })[0];
    if (versionLine) result.gradleVersion = versionLine.replace('Gradle ', '').trim().split(' ')[0];
  } catch (error) {
    result.gradle = false;
  }

  try {
    const javaPath = JAVA_HOME ? path.join(JAVA_HOME, 'bin', 'java') : 'java';
    const sync = require('child_process').spawnSync(javaPath, ['-version'], { env: buildEnv(), timeout: 20000 });
    const text = String(sync.stderr || '') + String(sync.stdout || '');
    const match = text.split(' ').filter(function (part) { return part.indexOf('version') >= 0; })[0];
    result.javaVersion = match ? match.replace('version', '').replace(/"/g, '').trim() : text.split(os.EOL)[0];
    result.java = sync.status === 0;
  } catch (error) {
    result.java = false;
  }

  toolCache = { at: now, value: result };
  return result;
}

function cleanup() {
  const cutoff = Date.now() - RETENTION_HOURS * 3600000;
  try {
    const dirs = fs.readdirSync(BUILD_ROOT);
    for (let i = 0; i < dirs.length; i += 1) {
      const dir = path.join(BUILD_ROOT, dirs[i]);
      const job = jobs.get(dirs[i]);
      if (job && (job.status === 'building' || job.status === 'queued')) continue;
      let stat = null;
      try { stat = fs.statSync(dir); } catch (error) { continue; }
      if (stat.mtimeMs < cutoff) {
        fs.rmSync(dir, { recursive: true, force: true });
        jobs.delete(dirs[i]);
      }
    }
  } catch (error) {
    process.stderr.write('Cleanup failed: ' + error.message + os.EOL);
  }
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}

function authorized(req) {
  if (!AUTH_TOKEN) return false;
  const header = String(req.headers.authorization || '');
  const token = header.indexOf('Bearer ') === 0 ? header.slice(7).trim() : '';
  if (!token) return false;
  const a = Buffer.from(token);
  const b = Buffer.from(AUTH_TOKEN);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function rateLimited(req) {
  const ip = (req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : '') || (req.socket.remoteAddress || 'unknown');
  const now = Date.now();
  const bucket = rateBuckets.get(ip);
  if (!bucket || now > bucket.resetAt) {
    rateBuckets.set(ip, { count: 1, resetAt: now + 60000 });
    return false;
  }
  bucket.count += 1;
  return bucket.count > RATE_LIMIT_PER_MINUTE;
}

function readBody(req) {
  return new Promise(function (resolve, reject) {
    let size = 0;
    const chunks = [];
    req.on('data', function (chunk) {
      size += chunk.length;
      if (size > REQUEST_LIMIT_BYTES) {
        reject(new Error('Request body is too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', function () {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(new Error('Request body must be valid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function streamArtifact(req, res, job, artifact) {
  const token = String(req.query.token || '');
  if (!token || token !== downloadToken(job.buildId, artifact)) {
    sendJson(res, 403, { error: 'Invalid or missing download token' });
    return;
  }
  const entry = artifactFile(job, artifact);
  if (!entry) {
    sendJson(res, 404, { error: 'That artifact does not exist for this build' });
    return;
  }
  const stat = fs.statSync(entry.file);
  res.writeHead(200, {
    'Content-Type': entry.type,
    'Content-Length': stat.size,
    'Content-Disposition': 'attachment; filename="' + entry.name + '"',
    'Cache-Control': 'private, max-age=0, no-store'
  });
  fs.createReadStream(entry.file).pipe(res);
}

const server = http.createServer(function (req, res) {
  const parsed = new URL(req.url, 'http://localhost');
  req.query = {};
  parsed.searchParams.forEach(function (value, key) { req.query[key] = value; });
  const pathname = parsed.pathname;
  const base = publicBaseUrl(req);

  if (req.method === 'GET' && pathname === '/health') {
    const health = checkHealth();
    health.queueSize = Array.from(jobs.values()).filter(function (job) { return job.status === 'queued'; }).length;
    health.currentBuilds = activeBuilds;
    sendJson(res, 200, health);
    return;
  }

  if (rateLimited(req)) {
    sendJson(res, 429, { error: 'Too many requests' });
    return;
  }

  if (req.method === 'GET' && pathname === '/') {
    sendJson(res, 200, {
      service: 'android-build-worker',
      version: VERSION,
      endpoints: ['GET /health', 'POST /build', 'GET /build/{buildId}/status', 'POST /build/{buildId}/cancel', 'GET /build/{buildId}/apk', 'GET /build/{buildId}/aab', 'GET /build/{buildId}/source']
    });
    return;
  }

  const parts = pathname.split('/').filter(Boolean);

  if (parts.length === 3 && parts[0] === 'build' && req.method === 'GET') {
    const job = jobs.get(parts[1]);
    if (!job) {
      sendJson(res, 404, { error: 'Unknown build id' });
      return;
    }
    const artifact = parts[2];
    if (artifact === 'apk' || artifact === 'aab' || artifact === 'source') {
      streamArtifact(req, res, job, artifact);
      return;
    }
  }

  if (!authorized(req)) {
    sendJson(res, 401, { error: 'Unauthorized: send Authorization: Bearer <WORKER_AUTH_TOKEN>' });
    return;
  }

  if (parts.length === 1 && parts[0] === 'build' && req.method === 'POST') {
    readBody(req).then(function (payload) {
      try {
        const job = enqueue(payload);
        sendJson(res, 202, {
          buildId: job.buildId,
          status: job.status,
          stage: job.stage,
          statusUrl: base + '/build/' + job.buildId + '/status',
          artifacts: {}
        });
      } catch (error) {
        sendJson(res, error.statusCode || 400, { error: error.message });
      }
    }).catch(function (error) {
      sendJson(res, 400, { error: error.message });
    });
    return;
  }

  if (parts.length === 3 && parts[0] === 'build' && parts[2] === 'status' && req.method === 'GET') {
    const job = jobs.get(parts[1]);
    if (!job) {
      sendJson(res, 404, { error: 'Unknown build id' });
      return;
    }
    sendJson(res, 200, publicJob(job, base));
    return;
  }

  if (parts.length === 3 && parts[0] === 'build' && parts[2] === 'cancel' && req.method === 'POST') {
    const job = jobs.get(parts[1]);
    if (!job) {
      sendJson(res, 404, { error: 'Unknown build id' });
      return;
    }
    job.cancelled = true;
    if (job.child) {
      try { job.child.kill('SIGKILL'); } catch (error) { /* already gone */ }
    }
    job.status = 'cancelled';
    job.finishedAt = Date.now();
    setStage(job, 'cancelled');
    sendJson(res, 200, publicJob(job, base));
    return;
  }

  sendJson(res, 404, { error: 'Not found' });
});

if (!AUTH_TOKEN) {
  process.stderr.write('WORKER_AUTH_TOKEN is not set. The worker will refuse every build request.' + os.EOL);
}

loadJobs();
fs.mkdirSync(GRADLE_HOME, { recursive: true });
cleanup();
setInterval(cleanup, 1800000);

server.listen(PORT, function () {
  process.stdout.write('Android build worker ' + VERSION + ' listening on port ' + PORT + os.EOL);
  process.stdout.write('Android SDK: ' + (SDK_ROOT || 'not configured') + os.EOL);
  process.stdout.write('Java home: ' + (JAVA_HOME || 'system default') + os.EOL);
});
