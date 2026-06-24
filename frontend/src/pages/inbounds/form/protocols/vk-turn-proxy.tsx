import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Divider, Form, Input, InputNumber, Modal, Select, Space, Switch } from 'antd';
import { MinusOutlined, PlusOutlined, ToolOutlined } from '@ant-design/icons';

import { HttpUtil, RandomUtil } from '@/utils';
import { useInboundOptions } from '@/api/queries/useInboundOptions';

// vk-turn-proxy is a standalone relay listener that decrypts client traffic
// and forwards it to a WireGuard or Hysteria2 inbound, or a raw host:port.
// The form is modeled closely on the wireguard inbound form: a Form.List for
// the VK links and another for clients, each client carrying an optional
// managed WG peer that the backend auto-provisions on save.

const FORWARD_TYPES = ['wireguardInbound', 'hysteria2Inbound', 'host'] as const;
const WRAP_MODES = ['off', 'optional', 'required'] as const;

// FixedConflict mirrors the backend FixedAllowedIPConflict payload, same as the
// wireguard inbound form. A vk-turn-proxy inbound provisions managed peers on
// its forward wireguard inbound, so the duplicate-allowedIP conflicts live
// there; the fixer targets that forward inbound by id.
interface FixedConflict {
  publicKey: string;
  oldIp: string;
  newIp: string;
  client: string;
}

export default function VkTurnProxyFields() {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const forwardType = (Form.useWatch(['settings', 'forward', 'type'], form) ?? 'host') as string;
  const forwardWgInboundId = Form.useWatch(['settings', 'forward', 'wireguardInboundId'], form) as
    | number
    | undefined;
  const [fixing, setFixing] = useState(false);

  const fixConflicts = async () => {
    if (forwardWgInboundId == null) return;
    setFixing(true);
    try {
      const msg = await HttpUtil.post<FixedConflict[]>(
        `/panel/api/inbounds/${forwardWgInboundId}/wireguard/fixAllowedIpConflicts`,
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

  const { data: inboundOptions } = useInboundOptions();
  const wireguardInbounds = (inboundOptions ?? []).filter((o) => o.protocol === 'wireguard');
  const hysteria2Inbounds = (inboundOptions ?? []).filter((o) => o.protocol === 'hysteria');

  const inboundLabel = (o: { id: number; remark?: string; tag?: string; port?: number }) =>
    `${o.remark || o.tag || `#${o.id}`}${o.port ? ` (:${o.port})` : ''}`;

  return (
    <>
      <Divider titlePlacement="center">{t('pages.inbounds.protocols.vkTurnProxy.forward')}</Divider>
      <Form.Item
        name={['settings', 'forward', 'type']}
        label={t('pages.inbounds.protocols.vkTurnProxy.forwardType')}
      >
        <Select
          options={FORWARD_TYPES.map((value) => ({
            value,
            label: t(`pages.inbounds.protocols.vkTurnProxy.forwardTypes.${value}`),
          }))}
        />
      </Form.Item>

      {forwardType === 'wireguardInbound' && (
        <>
          <Form.Item
            name={['settings', 'forward', 'wireguardInboundId']}
            label={t('pages.inbounds.protocols.vkTurnProxy.wireguardInbound')}
          >
            {wireguardInbounds.length > 0 ? (
              <Select
                allowClear
                options={wireguardInbounds.map((o) => ({ value: o.id, label: inboundLabel(o) }))}
              />
            ) : (
              <InputNumber min={0} style={{ width: '100%' }} />
            )}
          </Form.Item>
          {forwardWgInboundId != null && (
            <Form.Item label=" " colon={false}>
              <Button size="small" icon={<ToolOutlined />} loading={fixing} onClick={fixConflicts}>
                {t('pages.xray.wireguard.fixConflicts')}
              </Button>
            </Form.Item>
          )}
        </>
      )}

      {forwardType === 'hysteria2Inbound' && (
        <Form.Item
          name={['settings', 'forward', 'hysteria2InboundId']}
          label={t('pages.inbounds.protocols.vkTurnProxy.hysteria2Inbound')}
        >
          {hysteria2Inbounds.length > 0 ? (
            <Select
              allowClear
              options={hysteria2Inbounds.map((o) => ({ value: o.id, label: inboundLabel(o) }))}
            />
          ) : (
            <InputNumber min={0} style={{ width: '100%' }} />
          )}
        </Form.Item>
      )}

      {forwardType === 'host' && (
        <>
          <Form.Item name={['settings', 'forward', 'host']} label={t('pages.inbounds.protocols.vkTurnProxy.host')}>
            <Input placeholder="127.0.0.1" />
          </Form.Item>
          <Form.Item name={['settings', 'forward', 'port']} label={t('pages.inbounds.port')}>
            <InputNumber min={0} max={65535} />
          </Form.Item>
        </>
      )}

      <Divider titlePlacement="center">{t('pages.inbounds.protocols.vkTurnProxy.links')}</Divider>
      <Form.List name={['settings', 'links']}>
        {(fields, { add, remove }) => (
          <Form.Item label={t('pages.inbounds.protocols.vkTurnProxy.links')}>
            <Button size="small" onClick={() => add('')}>
              <PlusOutlined />
            </Button>
            {fields.map((field) => (
              <Space.Compact key={field.key} block className="mt-4">
                <Form.Item name={field.name} noStyle>
                  <Input />
                </Form.Item>
                <Button size="small" onClick={() => remove(field.name)}>
                  <MinusOutlined />
                </Button>
              </Space.Compact>
            ))}
          </Form.Item>
        )}
      </Form.List>
      <Form.Item name={['settings', 'link']} label={t('pages.inbounds.protocols.vkTurnProxy.link')}>
        <Input />
      </Form.Item>
      <Form.Item name={['settings', 'linkSecondary']} label={t('pages.inbounds.protocols.vkTurnProxy.linkSecondary')}>
        <Input />
      </Form.Item>

      <Divider titlePlacement="center">{t('pages.inbounds.protocols.vkTurnProxy.wgParams')}</Divider>
      <Form.Item name={['settings', 'sessionMode']} label={t('pages.inbounds.protocols.vkTurnProxy.sessionMode')}>
        <Input />
      </Form.Item>
      <Form.Item name={['settings', 'localEndpoint']} label={t('pages.inbounds.protocols.vkTurnProxy.localEndpoint')}>
        <Input />
      </Form.Item>
      <Form.Item name={['settings', 'wgDns']} label={t('pages.inbounds.protocols.vkTurnProxy.wgDns')}>
        <Input />
      </Form.Item>
      <Form.Item name={['settings', 'wgMtu']} label="MTU">
        <InputNumber min={1} />
      </Form.Item>
      <Form.Item name={['settings', 'wgAllowedIps']} label={t('pages.inbounds.protocols.vkTurnProxy.wgAllowedIps')}>
        <Input placeholder="0.0.0.0/0, ::/0" />
      </Form.Item>
      <Form.Item name={['settings', 'threads']} label={t('pages.inbounds.protocols.vkTurnProxy.threads')}>
        <InputNumber min={1} />
      </Form.Item>
      <Form.Item name={['settings', 'credsGroupSize']} label={t('pages.inbounds.protocols.vkTurnProxy.credsGroupSize')}>
        <InputNumber min={1} />
      </Form.Item>
      <Form.Item name={['settings', 'useUdp']} label={t('pages.inbounds.protocols.vkTurnProxy.useUdp')} valuePropName="checked">
        <Switch />
      </Form.Item>
      <Form.Item name={['settings', 'noObfuscation']} label={t('pages.inbounds.protocols.vkTurnProxy.noObfuscation')} valuePropName="checked">
        <Switch />
      </Form.Item>

      <Divider titlePlacement="center">{t('pages.inbounds.protocols.vkTurnProxy.wrap')}</Divider>
      <Form.Item name={['settings', 'wrapMode']} label={t('pages.inbounds.protocols.vkTurnProxy.wrapMode')}>
        <Select
          allowClear
          options={WRAP_MODES.map((value) => ({
            value,
            label: t(`pages.inbounds.protocols.vkTurnProxy.wrapModes.${value}`),
          }))}
        />
      </Form.Item>
      <Form.Item name={['settings', 'wrapCipher']} label={t('pages.inbounds.protocols.vkTurnProxy.wrapCipher')}>
        <Input />
      </Form.Item>
      <Form.Item name={['settings', 'wrapKeyHex']} label={t('pages.inbounds.protocols.vkTurnProxy.wrapKeyHex')}>
        <Input />
      </Form.Item>
      <Form.Item
        name={['settings', 'wrapAcceptClientKeys']}
        label={t('pages.inbounds.protocols.vkTurnProxy.wrapAcceptClientKeys')}
        valuePropName="checked"
      >
        <Switch />
      </Form.Item>

      <Divider titlePlacement="center">{t('pages.inbounds.protocols.vkTurnProxy.clients')}</Divider>
      <Form.List name={['settings', 'clients']}>
        {(fields, { add, remove }) => (
          <>
            <Form.Item label={t('pages.inbounds.protocols.vkTurnProxy.clients')}>
              <Button
                size="small"
                onClick={() =>
                  add({
                    id: RandomUtil.randomUUID(),
                    email: RandomUtil.randomLowerAndNum(10),
                    enable: true,
                    subId: RandomUtil.randomLowerAndNum(16),
                    peerManaged: true,
                  })
                }
              >
                <PlusOutlined /> {t('pages.inbounds.protocols.vkTurnProxy.addClient')}
              </Button>
            </Form.Item>
            {fields.map((field, idx) => (
              <div key={field.key} className="wg-peer">
                <Divider titlePlacement="center">
                  <Space>
                    <span>{t('pages.inbounds.protocols.vkTurnProxy.clientNumber', { n: idx + 1 })}</span>
                    <Button size="small" danger icon={<MinusOutlined />} onClick={() => remove(field.name)} />
                  </Space>
                </Divider>
                <Form.Item name={[field.name, 'id']} hidden noStyle>
                  <Input />
                </Form.Item>
                <Form.Item name={[field.name, 'subId']} hidden noStyle>
                  <Input />
                </Form.Item>
                <Form.Item name={[field.name, 'email']} label={t('pages.inbounds.email')}>
                  <Input />
                </Form.Item>
                <Form.Item name={[field.name, 'comment']} label={t('comment')}>
                  <Input />
                </Form.Item>
                <Form.Item name={[field.name, 'enable']} label={t('enable')} valuePropName="checked">
                  <Switch />
                </Form.Item>
                <Form.Item name={[field.name, 'totalGB']} label={t('pages.inbounds.protocols.vkTurnProxy.totalGB')}>
                  <InputNumber min={0} />
                </Form.Item>
                <Form.Item name={[field.name, 'expiryTime']} label={t('pages.inbounds.expireDate')}>
                  <InputNumber />
                </Form.Item>
                <Form.Item name={[field.name, 'limitIp']} label={t('pages.inbounds.protocols.vkTurnProxy.limitIp')}>
                  <InputNumber min={0} />
                </Form.Item>
                <Form.Item
                  name={[field.name, 'peerManaged']}
                  label={t('pages.inbounds.protocols.vkTurnProxy.peerManaged')}
                  valuePropName="checked"
                >
                  <Switch />
                </Form.Item>
                <Form.Item noStyle shouldUpdate>
                  {() => {
                    const managed = form.getFieldValue(['settings', 'clients', field.name, 'peerManaged']) as
                      | boolean
                      | undefined;
                    if (managed) {
                      return (
                        <Form.Item label={t('pages.inbounds.protocols.vkTurnProxy.peerPublicKey')}>
                          <Form.Item name={[field.name, 'peerPublicKey']} noStyle>
                            <Input disabled placeholder={t('pages.inbounds.protocols.vkTurnProxy.peerManagedHint')} />
                          </Form.Item>
                        </Form.Item>
                      );
                    }
                    return (
                      <>
                        <Form.Item
                          name={[field.name, 'peer', 'privateKey']}
                          label={t('pages.xray.wireguard.secretKey')}
                        >
                          <Input />
                        </Form.Item>
                        <Form.Item
                          name={[field.name, 'peer', 'publicKey']}
                          label={t('pages.xray.wireguard.publicKey')}
                        >
                          <Input />
                        </Form.Item>
                        <Form.Item name={[field.name, 'peer', 'preSharedKey']} label="PSK">
                          <Input />
                        </Form.Item>
                        <Form.List name={[field.name, 'peer', 'allowedIPs']}>
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
                                  <Button size="small" onClick={() => removeIp(ipField.name)}>
                                    <MinusOutlined />
                                  </Button>
                                </Space.Compact>
                              ))}
                            </Form.Item>
                          )}
                        </Form.List>
                      </>
                    );
                  }}
                </Form.Item>
              </div>
            ))}
          </>
        )}
      </Form.List>
    </>
  );
}
