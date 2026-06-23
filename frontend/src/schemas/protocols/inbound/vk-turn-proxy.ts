import { z } from 'zod';

// AntD InputNumber emits null (not undefined) when the user clears it, and
// the form store hands that null straight to safeParse on submit. A bare
// .optional() would reject null and block the save, so coerce null to
// undefined first. Mirrors the helper in wireguard.ts.
const optionalClearedInt = (schema: z.ZodNumber) =>
  z.preprocess((v) => (v == null ? undefined : v), schema.optional());

// Forward target the vk-turn-proxy relays decrypted traffic to. Either an
// existing WireGuard/Hysteria2 inbound on this panel (referenced by id) or a
// raw host:port. The discriminator is `type`; the other id/host/port fields
// ride along only for the matching branch and xray-core style consumers
// ignore the unused ones.
export const VkTurnProxyForwardSchema = z.object({
  type: z.enum(['wireguardInbound', 'hysteria2Inbound', 'host']),
  wireguardInboundId: optionalClearedInt(z.number().int().min(0)),
  hysteria2InboundId: optionalClearedInt(z.number().int().min(0)),
  host: z.string().optional(),
  port: optionalClearedInt(z.number().int().min(0).max(65535)),
});
export type VkTurnProxyForward = z.infer<typeof VkTurnProxyForwardSchema>;

// Managed WG peer for a vk-turn-proxy client. When peerManaged is true the
// backend auto-provisions the keypair and a unique AllowedIP on save, so
// these fields may all be absent on a freshly created client row.
export const VkTurnProxyClientPeerSchema = z.object({
  privateKey: z.string().optional(),
  publicKey: z.string().optional(),
  preSharedKey: z.string().optional(),
  allowedIPs: z.array(z.string()).default([]),
  keepAlive: optionalClearedInt(z.number().int().min(0)),
});
export type VkTurnProxyClientPeer = z.infer<typeof VkTurnProxyClientPeerSchema>;

export const VkTurnProxyClientSchema = z.object({
  id: z.string(),
  email: z.string(),
  enable: z.boolean(),
  comment: z.string().optional(),
  totalGB: optionalClearedInt(z.number().int().min(0)),
  expiryTime: optionalClearedInt(z.number().int()),
  limitIp: optionalClearedInt(z.number().int().min(0)),
  tgId: optionalClearedInt(z.number().int()),
  subId: z.string().optional(),
  reset: optionalClearedInt(z.number().int().min(0)),
  link: z.string().optional(),
  links: z.array(z.string()).optional(),
  linkSecondary: z.string().optional(),
  peerPublicKey: z.string().optional(),
  peerManaged: z.boolean().optional(),
  peer: VkTurnProxyClientPeerSchema.optional(),
});
export type VkTurnProxyClient = z.infer<typeof VkTurnProxyClientSchema>;

export const VkTurnProxyInboundSettingsSchema = z.object({
  forward: VkTurnProxyForwardSchema,
  link: z.string().optional(),
  links: z.array(z.string()).optional(),
  linkSecondary: z.string().optional(),
  sessionMode: z.string().optional(),
  localEndpoint: z.string().optional(),
  wgDns: z.string().optional(),
  wgMtu: optionalClearedInt(z.number().int().min(1)),
  wgAllowedIps: z.string().optional(),
  threads: optionalClearedInt(z.number().int().min(1)),
  useUdp: z.boolean().optional(),
  noObfuscation: z.boolean().optional(),
  credsGroupSize: optionalClearedInt(z.number().int().min(1)),
  wrapMode: z.string().optional(),
  wrapCipher: z.string().optional(),
  wrapKeyHex: z.string().optional(),
  wrapAcceptClientKeys: z.boolean().optional(),
  clients: z.array(VkTurnProxyClientSchema).default([]),
});
export type VkTurnProxyInboundSettings = z.infer<typeof VkTurnProxyInboundSettingsSchema>;
