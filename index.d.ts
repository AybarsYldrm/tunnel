// TypeScript tanımları — node-dtls
/// <reference types="node" />

import { EventEmitter } from 'node:events';
import { X509Certificate, KeyObject } from 'node:crypto';

export type ProtocolVersion = 'DTLSv1.2' | 'DTLSv1.3';

export type CipherSuiteName =
  | 'TLS_AES_128_GCM_SHA256'
  | 'TLS_AES_256_GCM_SHA384'
  | 'TLS_CHACHA20_POLY1305_SHA256'
  | 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
  | 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
  | 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
  | 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
  | 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'
  | 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256';

/**
 * Adlandırılmış şifreleme politikası — DTLS 1.3 ve 1.2 karşılıklarını birlikte,
 * doğru sırayla kurar.
 *
 *   balanced  (varsayılan) AES-128-GCM önce; AES-NI olan makinelerde en hızlı
 *   aes128 / aes256 / aes   yalnızca AES-GCM (FIPS uyumlu seçim)
 *   chacha20  yalnızca ChaCha20-Poly1305 — AES hızlandırması olmayan uçlar
 *   mobile    ChaCha20 önce, AES yedek — karışık istemci parkı
 */
export type CipherPolicyName =
  | 'balanced' | 'default' | 'auto'
  | 'aes' | 'aes-gcm' | 'fips'
  | 'aes128' | 'aes-128' | 'aes128gcm' | 'aes-128-gcm'
  | 'aes256' | 'aes-256' | 'aes256gcm' | 'aes-256-gcm' | 'strong'
  | 'chacha' | 'chacha20' | 'chacha20-poly1305' | 'poly1305'
  | 'mobile' | 'chacha-first' | 'arm' | 'embedded';

export type SrtpProfileName =
  | 'SRTP_AES128_CM_HMAC_SHA1_80'
  | 'SRTP_AES128_CM_HMAC_SHA1_32'
  | 'SRTP_AEAD_AES_128_GCM'
  | 'SRTP_AEAD_AES_256_GCM';

export type NamedGroupName = 'X25519' | 'SECP256R1' | 'SECP384R1' | 'SECP521R1';

export type CertInput = string | Buffer | X509Certificate | Array<string | Buffer>;

export interface PeerCertificate {
  subject: string;
  issuer: string;
  subjectAltName?: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint: string;
  fingerprint256: string;
  fingerprint512: string;
  keyType?: string;
  ca: boolean;
  raw: Buffer;
}

export interface SecureContextOptions {
  /** PEM zinciri (leaf önce) veya DER. */
  cert?: CertInput;
  key?: string | Buffer | KeyObject;
  passphrase?: string;
  /** Güvenilen kök sertifikalar. */
  ca?: CertInput;
}

export interface SecureContext {
  certDER: Buffer[] | null;
  certX509: X509Certificate[] | null;
  leaf: X509Certificate | null;
  privateKey: KeyObject | null;
  keyType: string | null;
  ca: X509Certificate[];
  /** Zımbalanacak OCSP yanıtı (DER) ya da onu üreten fonksiyon. */
  ocspResponse?: Buffer | ((ctx: SecureContext, socket: DtlsSocket) => Buffer | Promise<Buffer>) | null;
}

export interface SrtpOptions {
  enabled?: boolean;
  profiles?: Array<SrtpProfileName | number>;
  /** SSRC başına replay penceresi (varsayılan açık). */
  replayProtection?: boolean;
  /** RFC 7983 demux ile aynı soketten medya alınsın mı (varsayılan açık). */
  demux?: boolean;
}

/**
 * Güvenilir kanal (RFC 9002 — QUIC kayıp kurtarma modeli) seçenekleri.
 * Kayıp tespiti paket eşiği (3) + zaman eşiği (9/8·RTT) ile, gönderim hızı
 * NewReno tıkanıklık penceresiyle yönetilir; zamanaşımı PTO'dur.
 */
/**
 * Tıkanıklık denetleyicisi.
 *
 *  - `bbr3`    (varsayılan) BBRv3 — darboğaz bant genişliğini ve en küçük
 *              gecikmeyi ÖLÇER, kaybı tıkanıklık saymaz. Kayıplı ve uzun
 *              mesafeli hatlarda NewReno'ya göre kat kat verim; derin
 *              tamponlarda kuyruk gecikmesi üretmez.
 *  - `newreno` RFC 9002 §7 — kayıp odaklı, klasik davranış.
 */
export type CongestionControlName =
  | 'bbr3' | 'bbr' | 'bbrv3' | 'bbr-v3'
  | 'newreno' | 'new-reno' | 'reno' | 'rfc9002';

/** BBRv3 ince ayarları — varsayılanlar `BBR_DEFAULTS`. */
export interface BbrOptions {
  startupPacingGain?: number;
  startupCwndGain?: number;
  drainPacingGain?: number;
  cwndGain?: number;
  probeRttCwndGain?: number;
  minRttWindowMs?: number;
  probeRttDurationMs?: number;
  lossThresh?: number;
  beta?: number;
  headroom?: number;
  fullBwThresh?: number;
  fullBwCnt?: number;
  fullLossCnt?: number;
  pacingMargin?: number;
  minLossSamplePackets?: number;
  bwProbeWaitMs?: number;
  [key: string]: number | undefined;
}

export interface ReliableOptions {
  enabled?: boolean;
  /** Varsayılan false → SIRASIZ teslim (head-of-line blocking yok). */
  ordered?: boolean;
  /** Tıkanıklık denetimi; varsayılan `bbr3`. */
  congestionControl?: CongestionControlName;
  /** `congestionControl` için kısa ad. */
  cc?: CongestionControlName;
  /**
   * Hız şekillendirme (pacing). Verilmezse denetleyici karar verir: BBR açık,
   * NewReno kapalı. BBR için kapatmak önerilmez — model ölçtüğü hızda
   * göndermeyi ancak paketleri zamana yayarak yapabilir.
   */
  pacing?: boolean;
  bbr?: BbrOptions;
  /** Çerçeve başına yük sınırı; varsayılan mtu - 64. */
  mtu?: number;
  /** RTT örneği alınana kadarki başlangıç tahmini (ms, varsayılan 333). */
  initialRtt?: number;
  /** PTO alt/üst sınırları (ms). */
  minPto?: number;
  maxPto?: number;
  /** Karşı tarafa bildirilen azami ACK gecikmesi (ms, varsayılan 25). */
  maxAckDelay?: number;
  /** ACK'leri toplamak için gecikme (ms, varsayılan 10). */
  ackDelay?: number;
  /** Parça başına vazgeçme sınırı (varsayılan 12). */
  maxRetransmits?: number;
  /** İzlenen paket sayısı için sert bellek tavanı. */
  maxTrackedPackets?: number;
  maxReassembly?: number;
  maxOrderedBuffer?: number;

  /** @deprecated `initialRtt` kullanın. */
  rto?: number;
  /** @deprecated `initialRtt` kullanın. */
  initialRto?: number;
  /** @deprecated `minPto` kullanın. */
  minRto?: number;
  /** @deprecated `maxPto` kullanın. */
  maxRto?: number;
  /** @deprecated `maxTrackedPackets` kullanın. */
  maxInFlight?: number;
}

/** İptal (revocation) denetimi politikası — bkz. `revocation` seçeneği. */
export interface RevocationOptions {
  /**
   * - `'off'`        : denetim yapılmaz (varsayılan)
   * - `'soft-fail'`  : durum öğrenilemezse bağlantı SÜRER, sonuç raporlanır
   * - `'hard-fail'`  : durum öğrenilemezse handshake REDDEDİLİR
   */
  mode?: 'off' | 'soft-fail' | 'hard-fail';
  /** OCSP (RFC 6960) sorgusu yapılsın mı (varsayılan true). */
  ocsp?: boolean;
  /** CRL (RFC 5280 §5) indirilsin mi (varsayılan true). */
  crl?: boolean;
  /** Tek bir HTTP isteği için zaman aşımı (ms, varsayılan 5000). */
  timeoutMs?: number;
  /** Sonuçların önbellekte tutulma süresi (ms, varsayılan 10 dk). */
  cacheTtlMs?: number;
  maxCacheEntries?: number;
  /** OCSP yanıtı / CRL için boyut tavanı. */
  maxResponseBytes?: number;
  maxCrlBytes?: number;
  /** Saat kayması toleransı (ms, varsayılan 5 dk). */
  clockSkewMs?: number;
  /** CertID.hashAlgorithm (varsayılan 'sha256'). */
  hashAlgorithm?: 'sha1' | 'sha256' | 'sha384' | 'sha512';
  /** Yalnızca leaf denetlensin (varsayılan false → kök hariç tüm zincir). */
  checkLeafOnly?: boolean;
  /** Test/proxy için HTTP taşımasını değiştirir. */
  fetch?: (url: string, opts: Record<string, unknown>) => Promise<Buffer>;
}

export interface RevocationResult {
  /** Denetlenen sertifikanın konusu (subject). */
  subject: string;
  /** Durumu hangi yolla öğrendik. */
  method: 'ocsp' | 'ocsp-stapled' | 'crl' | 'skipped' | 'none';
  status: 'good' | 'revoked' | 'unknown';
  reason?: string;
  revokedAt?: number;
  url?: string;
  cached?: boolean;
  error: string | null;
}

export interface RevocationReport {
  ok: boolean;
  error: string | null;
  results: RevocationResult[];
}

export interface SendOptions {
  /** false → tek atım, yeniden gönderilmez (yalnızca reliable açıkken anlamlı). */
  reliable?: boolean;
  ordered?: boolean;
  streamId?: number;
}

export interface MessageMeta {
  streamId?: number;
  msgId?: number;
  ordered?: boolean;
  reliable?: boolean;
}

export interface CommonOptions extends SecureContextOptions {
  minVersion?: ProtocolVersion;
  maxVersion?: ProtocolVersion;

  /** Doğrulanamayan karşı tarafı reddet (varsayılan true). */
  rejectUnauthorized?: boolean;
  /** Kendinden imzalı leaf'i kabul et. */
  allowSelfSigned?: boolean;
  /** Parmak izi tabanlı güven (WebRTC tarzı). */
  peerFingerprint?: string | string[];
  peerFingerprintAlgorithm?: 'sha-1' | 'sha-256' | 'sha-512';
  /** Hata döndürürse handshake reddedilir. */
  verifyPeerCertificate?: (
    cert: PeerCertificate, chain: X509Certificate[], result: unknown
  ) => Error | null | undefined;
  checkServerIdentity?: (hostname: string, cert: PeerCertificate) => Error | null | undefined;
  /**
   * Sertifika iptal denetimi (OCSP / CRL). Zincirdeki KÖK HARİÇ her sertifika
   * denetlenir. `true` → 'soft-fail'.
   */
  revocation?: boolean | 'off' | 'soft-fail' | 'hard-fail' | RevocationOptions;
  /**
   * OCSP zımbalama talebi (status_request). Varsayılan: `revocation` açıksa
   * true. Sunucu yanıtı zımbalarsa istemci OCSP responder'ına hiç bağlanmaz.
   */
  requestOCSP?: boolean;
  /** Leaf sertifikanın EKU amacını (serverAuth/clientAuth) doğrula (varsayılan true). */
  checkPurpose?: boolean;

  /**
   * Şifreleme paketi tercihi. Üç biçim de kabul edilir:
   *
   *   'chacha20'                        adlandırılmış politika
   *   ['TLS_AES_128_GCM_SHA256', ...]   açık liste (ad ya da sayısal ID)
   *   ['chacha20', 'aes128']            politikaların birleşimi
   *
   * Sıra ÖNEMLİDİR: sunucu bunu tercih sırası olarak kullanır. Politika adı
   * DTLS 1.3 ve 1.2 karşılıklarını birlikte kurar.
   */
  cipherSuites?: CipherPolicyName | Array<CipherSuiteName | CipherPolicyName | number>;
  /** `cipherSuites` ile eşanlamlı — yapılandırma dosyaları için kısa ad. */
  cipher?: CipherPolicyName | Array<CipherSuiteName | CipherPolicyName | number>;
  groups?: Array<NamedGroupName | number>;
  sigSchemes?: Array<string | number>;
  alpn?: string | string[];

  srtp?: boolean | SrtpOptions;
  reliable?: boolean | ReliableOptions;

  /** RFC 7627 Extended Master Secret (DTLS 1.2), varsayılan true. */
  extendedMasterSecret?: boolean;
  /** Cookie takası ile DoS koruması, varsayılan true. */
  cookie?: boolean;
  mtu?: number;
  handshakeTimeout?: number;
  replayWindow?: number;
  /** Wireshark için NSS anahtar günlüğü yolu. */
  keylogFile?: string;
}

export interface ServerOptions extends CommonOptions {
  /** mTLS: istemciden sertifika iste. */
  requestCert?: boolean;
  /** SNI: hostname → sertifika bağlamı tablosu. */
  contexts?: Record<string, SecureContextOptions | SecureContext>;
  /** SNI: dinamik sertifika seçimi. */
  SNICallback?: (
    servername: string,
    cb: (err: Error | null, ctx?: SecureContextOptions | SecureContext) => void
  ) => void | Promise<SecureContextOptions | SecureContext>;

  idleTimeout?: number;
  maxSessions?: number;
  rateLimitBurst?: number;
  rateLimitPerSec?: number;
}

export interface ConnectOptions extends CommonOptions {
  host?: string;
  port: number;
  /** SNI ve hostname doğrulaması için beklenen sunucu adı. */
  servername?: string;
  sni?: string;
  localAddress?: string;
  localPort?: number;
  onLog?: (level: string, message: string, meta?: unknown) => void;
}

export interface ReliableStats {
  sent: number;
  resent: number;
  acked: number;
  received: number;
  duplicates: number;
  bytesSent: number;
  bytesReceived: number;
  giveUps: number;
  probes: number;
  lost: number;
}

/** BBR modelinin evresi. */
export type BbrState =
  | 'startup' | 'drain'
  | 'probe-bw-down' | 'probe-bw-cruise' | 'probe-bw-refill' | 'probe-bw-up'
  | 'probe-rtt';

/** `channel.getStats()` — ReliableStats + RFC 9002 kurtarma göstergeleri. */
export interface RecoveryStats extends ReliableStats {
  smoothedRtt: number;
  rttvar: number;
  minRtt: number | null;
  latestRtt: number;
  pto: number;
  ptoCount: number;
  congestionWindow: number;
  bytesInFlight: number;
  ssthresh: number | null;
  inFlightPackets: number;
  queued: number;
  packetsSent: number;
  packetsAcked: number;
  packetsLost: number;
  probesSent: number;
  congestionEvents: number;
  persistentCongestion: number;
  bytesLost: number;

  /** Yürürlükteki denetleyici: 'bbr3' ya da 'newreno'. */
  cc: 'bbr3' | 'newreno';
  /** Denetleyicinin durumu — BBR'da evre adı, NewReno'da 'slow-start'/'avoidance'. */
  state: BbrState | 'slow-start' | 'avoidance';
  /** Ölçülen darboğaz bant genişliği (bayt/s). NewReno'da null. */
  bandwidthBps: number | null;
  /** Hedef gönderim hızı (bayt/s). Şekillendirme kapalıysa null. */
  pacingRateBps: number | null;
  pacingEnabled: boolean;
  /** Uygulama veri üretemediği için hattı boş bıraktık mı. */
  appLimited: boolean;
  /** BBR: bant genişliği-gecikme çarpımı (bayt). */
  bdp?: number | null;
  /** BBR: ACK yığılması telafisi (bayt). */
  extraAcked?: number;
  /** BBR: başlangıç evresinden çıkış sebebi. */
  startupExit?: 'bandwidth-plateau' | 'loss' | null;
  probeRttCount?: number;
}

export interface ReliableChannel extends EventEmitter {
  readonly stats: ReliableStats;
  readonly rttMs: number | null;
  readonly inFlight: number;
  readonly congestionWindow: number;
  /** Hedef gönderim hızı (bayt/s); şekillendirme kapalıysa null. */
  readonly pacingRate: number | null;
  /** Yürürlükteki tıkanıklık denetleyicisinin adı. */
  readonly congestionControl: 'bbr3' | 'newreno';
  getStats(): RecoveryStats;
  sendMessage(data: Buffer, opts?: SendOptions): Promise<number>;
  sendUnreliable(data: Buffer): unknown;
  ping(token?: number): unknown;
  close(err?: Error): void;
}

export interface SocketInfo {
  protocol: ProtocolVersion | null;
  cipher: string | null;
  servername: string | null;
  alpnProtocol: string | null;
  authorized: boolean;
  authorizationError: string | null;
  srtpProfile: string | null;
  reliable: boolean;
  peer: { address: string; port: number } | null;
}

export class DtlsSocket extends EventEmitter {
  readonly protocol: ProtocolVersion | null;
  readonly cipher: string | null;
  readonly srtpProfile: string | null;
  readonly alpnProtocol: string | null;
  readonly servername: string | null;
  readonly remoteAddress: string | null;
  readonly remotePort: number | null;
  readonly localPort: number | null;
  readonly authorized: boolean;
  readonly authorizationError: string | null;
  readonly peerCertificateChain: X509Certificate[] | null;
  /** Doğrulanmış yol: leaf → ara CA'lar → güven çıpası. */
  readonly peerCertificatePath: X509Certificate[] | null;
  /** İptal denetimi sonucu (`revocation` kapalıysa null). */
  readonly peerRevocation: RevocationReport | null;
  /** Karşı tarafın zımbaladığı ham OCSP yanıtı (DER), varsa. */
  readonly peerOcspStaple: Buffer | null;
  readonly handshakeComplete: boolean;
  readonly closed: boolean;
  readonly reliable: ReliableChannel | null;

  send(data: Buffer | string, opts?: SendOptions): Promise<unknown>;
  write(data: Buffer | string, opts?: SendOptions): Promise<unknown>;
  close(): Promise<void>;
  end(): Promise<void>;
  destroy(err?: Error | null): void;

  /** Yalnızca SRTP müzakere edildiyse. */
  sendMedia(rtpPacket: Buffer): unknown;
  sendRtcp(rtcpPacket: Buffer): unknown;

  /** Yalnızca DTLS 1.3. */
  requestKeyUpdate(requestPeer?: boolean): Promise<void>;

  /** RFC 5705 / RFC 8446 §7.5. */
  exportKeyingMaterial(label: string, context: Buffer | null, length: number): Buffer;

  getPeerCertificate(): PeerCertificate | null;
  getInfo(): SocketInfo;

  on(event: 'connect' | 'handshake', listener: () => void): this;
  on(event: 'data', listener: (data: Buffer, meta?: MessageMeta) => void): this;
  on(event: 'media' | 'rtcp', listener: (packet: Buffer) => void): this;
  on(event: 'alert', listener: (a: { level: number; description: number; descriptionName: string }) => void): this;
  on(event: 'peer-certificate', listener: (cert: PeerCertificate, chain: X509Certificate[]) => void): this;
  on(event: 'srtp', listener: (info: { profile: number; name: string }) => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: 'close', listener: (err: Error | null) => void): this;
  on(event: 'log', listener: (level: string, message: string, meta?: unknown) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

export interface ServerStats {
  accepted: number;
  rejected: number;
  rateLimited: number;
  handshakeFailures: number;
}

export class DtlsServer extends EventEmitter {
  constructor(options: ServerOptions);
  readonly sessions: Map<string, DtlsSocket>;
  readonly stats: ServerStats;

  listen(port?: number, host?: string): Promise<{ address: string; port: number; family: string }>;
  address(): { address: string; port: number; family: string } | null;
  close(): Promise<void>;

  on(event: 'listening', listener: (addr: { address: string; port: number }) => void): this;
  on(event: 'connection' | 'secureConnection' | 'session', listener: (sock: DtlsSocket) => void): this;
  on(event: 'sessionError', listener: (err: Error, sock: DtlsSocket) => void): this;
  on(event: 'unhandled', listener: (datagram: Buffer, rinfo: { address: string; port: number }) => void): this;
  on(event: 'ratelimit' | 'overload', listener: (rinfo: { address: string; port: number }) => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: 'close', listener: () => void): this;
  on(event: 'log', listener: (level: string, message: string, meta?: unknown) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

export function createServer(
  options: ServerOptions,
  onSecureConnection?: (sock: DtlsSocket) => void
): DtlsServer;

export function connect(options: ConnectOptions): Promise<DtlsSocket>;

export function createSecureContext(options: SecureContextOptions): SecureContext;
export function setLogLevel(level: 'TRACE' | 'DEBUG' | 'INFO' | 'WARN' | 'ERROR'): void;

/** RFC 7983 paket ayrıştırma. */
export function demuxPacket(buf: Buffer): 'stun' | 'dtls' | 'turn' | 'rtp' | 'rtcp' | 'unknown';

export function createStunBindingResponse(
  request: Buffer, serverIp: string, serverPort: number, icePwd: string
): Buffer | null;

export class SrtpContext {
  constructor(opts: { profile?: number; masterKey: Buffer; masterSalt: Buffer; replayProtection?: boolean });
  readonly name: string;
  protectRtp(rtp: Buffer): Buffer;
  unprotectRtp(pkt: Buffer): Buffer;
  protectRtcp(rtcp: Buffer): Buffer;
  unprotectRtcp(pkt: Buffer): Buffer;
}

export const constants: {
  VERSION: Record<string, number>;
  CIPHER_SUITE: Record<string, number>;
  SRTP_PROFILE: Record<string, number>;
  NAMED_GROUP: Record<string, number>;
  SIG_SCHEME: Record<string, number>;
  ALERT_DESC: Record<string, number>;
  [k: string]: unknown;
};

export const VERSION: Record<string, number>;
export const CIPHER_SUITE: Record<string, number>;
export const SRTP_PROFILE: Record<string, number>;
export const NAMED_GROUP: Record<string, number>;
export const ALERT_DESC: Record<string, number>;
