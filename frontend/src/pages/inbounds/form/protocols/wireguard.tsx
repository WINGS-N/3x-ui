import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Divider, Form, Input, InputNumber, Modal, Select, Space, Switch } from 'antd';
import { MinusOutlined, PlusOutlined, ReloadOutlined, ToolOutlined } from '@ant-design/icons';

import { HttpUtil, Wireguard } from '@/utils';
import { useOutboundTags } from '@/api/queries/useOutboundTags';

interface WireguardFieldsProps {
  wgPubKey: string;
  regenInboundWg: () => void;
  regenWgPeerKeypair: (name: number) => void;
  // Id of the existing inbound being edited, or null when creating a new
  // one. The conflict fixer needs a persisted inbound to act on.
  inboundId: number | null;
}

// FixedConflict mirrors the backend FixedAllowedIPConflict payload.
interface FixedConflict {
  publicKey: string;
  oldIp: string;
  newIp: string;
  client: string;
}

function nextWgPeerAllowedIP(peers: Array<{ allowedIPs?: string[] }> | undefined): string {
  const fallback = '10.0.0.2/32';
  let maxInt = -1;
  let prefix = 32;
  for (const peer of peers ?? []) {
    for (const ip of peer?.allowedIPs ?? []) {
      const m = /^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?\s*$/.exec(String(ip));
      if (!m) continue;
      const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
      if (octets.some((o) => o > 255)) continue;
      const asInt = octets[0] * 16777216 + octets[1] * 65536 + octets[2] * 256 + octets[3];
      if (asInt > maxInt) {
        maxInt = asInt;
        prefix = m[5] !== undefined ? Math.min(Number(m[5]), 32) : 32;
      }
    }
  }
  if (maxInt < 0) return fallback;
  const next = maxInt + 1;
  const a = Math.floor(next / 16777216) % 256;
  const b = Math.floor(next / 65536) % 256;
  const c = Math.floor(next / 256) % 256;
  const d = next % 256;
  return `${a}.${b}.${c}.${d}/${prefix}`;
}

export default function WireguardFields({ wgPubKey, regenInboundWg, regenWgPeerKeypair, inboundId }: WireguardFieldsProps) {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const { data: outboundTags } = useOutboundTags();
  const [fixing, setFixing] = useState(false);

  const fixConflicts = async () => {
    if (inboundId == null) return;
    setFixing(true);
    try {
      const msg = await HttpUtil.post<FixedConflict[]>(
        `/panel/api/inbounds/${inboundId}/wireguard/fixAllowedIpConflicts`,
      );
      if (!msg.success) return;
      const fixed = msg.obj ?? [];
      Modal.info({
        title: t('pages.xray.wireguard.fixedConflictsTitle'),
        content:
          fixed.length === 0 ? (
            <span>{t('pages.xray.wireguard.noConflicts')}</span>
          ) : (
            <ul style={{ paddingInlineStart: 16, marginBottom: 0 }}>
              {fixed.map((c) => (
                <li key={`${c.publicKey}-${c.oldIp}`}>
                  {(c.client || c.publicKey)}: {c.oldIp} {'->'} {c.newIp}
                </li>
              ))}
            </ul>
          ),
      });
    } finally {
      setFixing(false);
    }
  };

  return (
    <>
      <Form.Item label={t('pages.xray.wireguard.secretKey')}>
        <Space.Compact block>
          <Form.Item name={['settings', 'secretKey']} noStyle>
            <Input style={{ width: 'calc(100% - 32px)' }} />
          </Form.Item>
          <Button aria-label={t('regenerate')} icon={<ReloadOutlined />} onClick={regenInboundWg} />
        </Space.Compact>
      </Form.Item>
      <Form.Item label={t('pages.xray.wireguard.publicKey')}>
        <Input value={wgPubKey} disabled />
      </Form.Item>
      <Form.Item name={['settings', 'mtu']} label="MTU">
        <InputNumber />
      </Form.Item>
      <Form.Item name={['settings', 'dns']} label={t('pages.inbounds.info.dns')}>
        <Input placeholder="1.1.1.1, 1.0.0.1" />
      </Form.Item>
      <Form.Item
        name={['settings', 'noKernelTun']}
        label={t('pages.inbounds.info.noKernelTun')}
        valuePropName="checked"
      >
        <Switch />
      </Form.Item>
      <Form.Item name={['settings', 'domainStrategy']} label={t('pages.xray.wireguard.domainStrategy')}>
        <Select
          allowClear
          options={[
            { value: 'ForceIP', label: 'ForceIP' },
            { value: 'ForceIPv4', label: 'ForceIPv4' },
            { value: 'ForceIPv4v6', label: 'ForceIPv4v6' },
            { value: 'ForceIPv6', label: 'ForceIPv6' },
            { value: 'ForceIPv6v4', label: 'ForceIPv6v4' },
          ]}
        />
      </Form.Item>
      <Form.Item
        name={['settings', 'outboundTag']}
        label={t('pages.inbounds.form.egressOutbound')}
        tooltip={t('pages.inbounds.form.egressOutboundHint')}
      >
        <Select
          allowClear
          showSearch
          placeholder={t('pages.inbounds.form.egressOutboundPlaceholder')}
          options={(outboundTags ?? []).map((tag) => ({ value: tag, label: tag }))}
        />
      </Form.Item>
      <Form.List name={['settings', 'peers']}>
        {(fields, { add, remove }) => (
          <>
            <Form.Item label={t('pages.inbounds.form.peers')}>
              <Space wrap>
                <Button
                  size="small"
                  onClick={() => {
                    const kp = Wireguard.generateKeypair();
                    const peers = form.getFieldValue(['settings', 'peers']) as Array<{ allowedIPs?: string[] }> | undefined;
                    add({
                      privateKey: kp.privateKey,
                      publicKey: kp.publicKey,
                      allowedIPs: [nextWgPeerAllowedIP(peers)],
                      keepAlive: 0,
                    });
                  }}
                >
                  <PlusOutlined /> {t('pages.inbounds.form.addPeer')}
                </Button>
                {inboundId != null && (
                  <Button size="small" icon={<ToolOutlined />} loading={fixing} onClick={fixConflicts}>
                    {t('pages.xray.wireguard.fixConflicts')}
                  </Button>
                )}
              </Space>
            </Form.Item>
            {fields.map((field, idx) => (
              <div key={field.key} className="wg-peer">
                <Divider titlePlacement="center">
                  <Space>
                    <span>{t('pages.inbounds.info.peerNumber', { n: idx + 1 })}</span>
                    <Form.Item noStyle shouldUpdate>
                      {() => {
                        const comment = form.getFieldValue(['settings', 'peers', field.name, 'comment']) as string | undefined;
                        return comment ? <span style={{ opacity: 0.65 }}>— {comment}</span> : null;
                      }}
                    </Form.Item>
                    {fields.length > 1 && (
                      <Button
                        size="small"
                        danger
                        icon={<MinusOutlined />}
                        onClick={() => remove(field.name)}
                      />
                    )}
                  </Space>
                </Divider>
                <Form.Item name={[field.name, 'comment']} label={t('comment')}>
                  <Input placeholder="e.g. Alice's laptop" />
                </Form.Item>
                <Form.Item label={t('pages.xray.wireguard.secretKey')}>
                  <Space.Compact block>
                    <Form.Item name={[field.name, 'privateKey']} noStyle>
                      <Input style={{ width: 'calc(100% - 32px)' }} />
                    </Form.Item>
                    <Button
                      icon={<ReloadOutlined />}
                      onClick={() => regenWgPeerKeypair(field.name)}
                    />
                  </Space.Compact>
                </Form.Item>
                <Form.Item name={[field.name, 'publicKey']} label={t('pages.xray.wireguard.publicKey')}>
                  <Input />
                </Form.Item>
                <Form.Item name={[field.name, 'preSharedKey']} label="PSK">
                  <Input />
                </Form.Item>
                <Form.List name={[field.name, 'allowedIPs']}>
                  {(ipFields, { add: addIp, remove: removeIp }) => (
                    <Form.Item label={t('pages.xray.wireguard.allowedIPs')}>
                      <Button size="small" onClick={() => addIp('')}>
                        <PlusOutlined />
                      </Button>
                      {ipFields.map((ipField) => (
                        <Space.Compact key={ipField.key} block className="mt-4">
                          <Form.Item name={ipField.name} noStyle>
                            <Input />
                          </Form.Item>
                          {ipFields.length > 1 && (
                            <Button size="small" onClick={() => removeIp(ipField.name)}>
                              <MinusOutlined />
                            </Button>
                          )}
                        </Space.Compact>
                      ))}
                    </Form.Item>
                  )}
                </Form.List>
                <Form.Item name={[field.name, 'keepAlive']} label={t('pages.inbounds.form.keepAlive')}>
                  <InputNumber min={0} />
                </Form.Item>
              </div>
            ))}
          </>
        )}
      </Form.List>
    </>
  );
}
