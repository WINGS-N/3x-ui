import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Divider, Form, Input, InputNumber, Modal, Select, Space, Switch } from 'antd';
import { MinusOutlined, PlusOutlined, ToolOutlined } from '@ant-design/icons';
import { useFieldArray, useFormContext, useWatch } from 'react-hook-form';

import { HttpUtil, RandomUtil } from '@/utils';
import { FormField } from '@/components/form/rhf';
import { useInboundOptions } from '@/api/queries/useInboundOptions';

// vk-turn-proxy is a standalone relay listener that decrypts client traffic
// and forwards it to a WireGuard or Hysteria2 inbound, or a raw host:port.
// The form is modeled closely on the wireguard inbound form: a field array for
// the clients, each carrying an optional managed WG peer that the backend
// auto-provisions on save.

const FORWARD_TYPES = ['wireguardInbound', 'hysteria2Inbound', 'host'] as const;
const WRAP_MODES = ['off', 'optional', 'required'] as const;

// String lists (VK links, peer allowedIPs) are edited as one comma-separated
// input, matching how upstream edits a client's allowedIPs. The transform keeps
// the stored value an array, so the wire payload shape is unchanged.
const csvList = {
  input: (value: unknown) => (Array.isArray(value) ? value.join(', ') : (value ?? '')),
  output: (value: unknown) =>
    String(value ?? '')
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry !== ''),
};

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

function VkTurnClientRow({ index, onRemove }: { index: number; onRemove: () => void }) {
  const { t } = useTranslation();
  const { control } = useFormContext();
  const managed = useWatch({ control, name: `settings.clients.${index}.peerManaged` }) as
    | boolean
    | undefined;

  return (
    <div className="wg-peer">
      <Divider titlePlacement="center">
        <Space>
          <span>{t('pages.inbounds.protocols.vkTurnProxy.clientNumber', { n: index + 1 })}</span>
          <Button size="small" danger icon={<MinusOutlined />} onClick={onRemove} />
        </Space>
      </Divider>
      <FormField name={['settings', 'clients', index, 'email']} label={t('pages.inbounds.email')}>
        <Input />
      </FormField>
      <FormField name={['settings', 'clients', index, 'comment']} label={t('comment')}>
        <Input />
      </FormField>
      <FormField name={['settings', 'clients', index, 'enable']} label={t('enable')} valueProp="checked">
        <Switch />
      </FormField>
      <FormField
        name={['settings', 'clients', index, 'totalGB']}
        label={t('pages.inbounds.protocols.vkTurnProxy.totalGB')}
      >
        <InputNumber min={0} />
      </FormField>
      <FormField name={['settings', 'clients', index, 'expiryTime']} label={t('pages.inbounds.expireDate')}>
        <InputNumber />
      </FormField>
      <FormField
        name={['settings', 'clients', index, 'limitIp']}
        label={t('pages.inbounds.protocols.vkTurnProxy.limitIp')}
      >
        <InputNumber min={0} />
      </FormField>
      <FormField
        name={['settings', 'clients', index, 'peerManaged']}
        label={t('pages.inbounds.protocols.vkTurnProxy.peerManaged')}
        valueProp="checked"
      >
        <Switch />
      </FormField>
      {managed ? (
        <FormField
          name={['settings', 'clients', index, 'peerPublicKey']}
          label={t('pages.inbounds.protocols.vkTurnProxy.peerPublicKey')}
        >
          <Input disabled placeholder={t('pages.inbounds.protocols.vkTurnProxy.peerManagedHint')} />
        </FormField>
      ) : (
        <>
          <FormField
            name={['settings', 'clients', index, 'peer', 'privateKey']}
            label={t('pages.xray.wireguard.secretKey')}
          >
            <Input />
          </FormField>
          <FormField
            name={['settings', 'clients', index, 'peer', 'publicKey']}
            label={t('pages.xray.wireguard.publicKey')}
          >
            <Input />
          </FormField>
          <FormField name={['settings', 'clients', index, 'peer', 'preSharedKey']} label="PSK">
            <Input />
          </FormField>
          <FormField
            name={['settings', 'clients', index, 'peer', 'allowedIPs']}
            label={t('pages.xray.wireguard.allowedIPs')}
            transform={csvList}
          >
            <Input placeholder="10.0.0.2/32" />
          </FormField>
        </>
      )}
    </div>
  );
}

export default function VkTurnProxyFields() {
  const { t } = useTranslation();
  const { control } = useFormContext();
  const forwardType = (useWatch({ control, name: 'settings.forward.type' }) ?? 'host') as string;
  const forwardWgInboundId = useWatch({ control, name: 'settings.forward.wireguardInboundId' }) as
    | number
    | undefined;
  const [fixing, setFixing] = useState(false);
  const { fields, append, remove } = useFieldArray({ control, name: 'settings.clients' });

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
      <FormField
        name={['settings', 'forward', 'type']}
        label={t('pages.inbounds.protocols.vkTurnProxy.forwardType')}
      >
        <Select
          options={FORWARD_TYPES.map((value) => ({
            value,
            label: t(`pages.inbounds.protocols.vkTurnProxy.forwardTypes.${value}`),
          }))}
        />
      </FormField>

      {forwardType === 'wireguardInbound' && (
        <>
          <FormField
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
          </FormField>
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
        <FormField
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
        </FormField>
      )}

      {forwardType === 'host' && (
        <>
          <FormField name={['settings', 'forward', 'host']} label={t('pages.inbounds.protocols.vkTurnProxy.host')}>
            <Input placeholder="127.0.0.1" />
          </FormField>
          <FormField name={['settings', 'forward', 'port']} label={t('pages.inbounds.port')}>
            <InputNumber min={0} max={65535} />
          </FormField>
        </>
      )}

      <Divider titlePlacement="center">{t('pages.inbounds.protocols.vkTurnProxy.links')}</Divider>
      <FormField
        name={['settings', 'links']}
        label={t('pages.inbounds.protocols.vkTurnProxy.links')}
        transform={csvList}
      >
        <Input.TextArea autoSize={{ minRows: 1, maxRows: 4 }} />
      </FormField>
      <FormField name={['settings', 'link']} label={t('pages.inbounds.protocols.vkTurnProxy.link')}>
        <Input />
      </FormField>
      <FormField name={['settings', 'linkSecondary']} label={t('pages.inbounds.protocols.vkTurnProxy.linkSecondary')}>
        <Input />
      </FormField>

      <Divider titlePlacement="center">{t('pages.inbounds.protocols.vkTurnProxy.wgParams')}</Divider>
      <FormField name={['settings', 'sessionMode']} label={t('pages.inbounds.protocols.vkTurnProxy.sessionMode')}>
        <Input />
      </FormField>
      <FormField name={['settings', 'localEndpoint']} label={t('pages.inbounds.protocols.vkTurnProxy.localEndpoint')}>
        <Input />
      </FormField>
      <FormField name={['settings', 'wgDns']} label={t('pages.inbounds.protocols.vkTurnProxy.wgDns')}>
        <Input />
      </FormField>
      <FormField name={['settings', 'wgMtu']} label="MTU">
        <InputNumber min={1} />
      </FormField>
      <FormField name={['settings', 'wgAllowedIps']} label={t('pages.inbounds.protocols.vkTurnProxy.wgAllowedIps')}>
        <Input placeholder="0.0.0.0/0, ::/0" />
      </FormField>
      <FormField name={['settings', 'threads']} label={t('pages.inbounds.protocols.vkTurnProxy.threads')}>
        <InputNumber min={1} />
      </FormField>
      <FormField name={['settings', 'credsGroupSize']} label={t('pages.inbounds.protocols.vkTurnProxy.credsGroupSize')}>
        <InputNumber min={1} />
      </FormField>
      <FormField name={['settings', 'useUdp']} label={t('pages.inbounds.protocols.vkTurnProxy.useUdp')} valueProp="checked">
        <Switch />
      </FormField>
      <FormField
        name={['settings', 'noObfuscation']}
        label={t('pages.inbounds.protocols.vkTurnProxy.noObfuscation')}
        valueProp="checked"
      >
        <Switch />
      </FormField>

      <Divider titlePlacement="center">{t('pages.inbounds.protocols.vkTurnProxy.wrap')}</Divider>
      <FormField name={['settings', 'wrapMode']} label={t('pages.inbounds.protocols.vkTurnProxy.wrapMode')}>
        <Select
          allowClear
          options={WRAP_MODES.map((value) => ({
            value,
            label: t(`pages.inbounds.protocols.vkTurnProxy.wrapModes.${value}`),
          }))}
        />
      </FormField>
      <FormField name={['settings', 'wrapCipher']} label={t('pages.inbounds.protocols.vkTurnProxy.wrapCipher')}>
        <Input />
      </FormField>
      <FormField name={['settings', 'wrapKeyHex']} label={t('pages.inbounds.protocols.vkTurnProxy.wrapKeyHex')}>
        <Input />
      </FormField>
      <FormField
        name={['settings', 'wrapAcceptClientKeys']}
        label={t('pages.inbounds.protocols.vkTurnProxy.wrapAcceptClientKeys')}
        valueProp="checked"
      >
        <Switch />
      </FormField>

      <Divider titlePlacement="center">{t('pages.inbounds.protocols.vkTurnProxy.panel')}</Divider>
      <FormField
        name={['settings', 'panelGrpc']}
        label={t('pages.inbounds.protocols.vkTurnProxy.panelGrpc')}
        tooltip={t('pages.inbounds.protocols.vkTurnProxy.panelGrpcHint')}
      >
        <Input placeholder="v.wingsnet.org:443" />
      </FormField>
      <FormField
        name={['settings', 'nodeId']}
        label={t('pages.inbounds.protocols.vkTurnProxy.nodeId')}
        tooltip={t('pages.inbounds.protocols.vkTurnProxy.nodeIdHint')}
      >
        <Input />
      </FormField>
      <FormField name={['settings', 'panelToken']} label={t('pages.inbounds.protocols.vkTurnProxy.panelToken')}>
        <Input />
      </FormField>
      <FormField
        name={['settings', 'panelCaPin']}
        label={t('pages.inbounds.protocols.vkTurnProxy.panelCaPin')}
        tooltip={t('pages.inbounds.protocols.vkTurnProxy.panelCaPinHint')}
      >
        <Input placeholder="sha256/..." />
      </FormField>
      <FormField
        name={['settings', 'panelInsecure']}
        label={t('pages.inbounds.protocols.vkTurnProxy.panelInsecure')}
        tooltip={t('pages.inbounds.protocols.vkTurnProxy.panelInsecureHint')}
        valueProp="checked"
      >
        <Switch />
      </FormField>

      <Divider titlePlacement="center">{t('pages.inbounds.protocols.vkTurnProxy.clients')}</Divider>
      <Form.Item label={t('pages.inbounds.protocols.vkTurnProxy.clients')}>
        <Button
          size="small"
          onClick={() =>
            append({
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
        <VkTurnClientRow key={field.id} index={idx} onRemove={() => remove(idx)} />
      ))}
    </>
  );
}
