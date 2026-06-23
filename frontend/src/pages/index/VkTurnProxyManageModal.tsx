import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Modal, Radio, Space, Spin, Tag } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';

import { HttpUtil } from '@/utils';
import './VersionModal.css';

interface BusyEvent {
  busy: boolean;
  tip?: string;
}

interface VkTurnProxyManageModalProps {
  open: boolean;
  onClose: () => void;
  onBusy: (e: BusyEvent) => void;
}

interface VkTurnStatus {
  available: boolean;
  total: number;
  enabled: number;
  running: number;
  state: string;
  errorMsg: string;
  version: string;
  uptime: number;
}

// Management panel for the standalone vk-turn-proxy relay binary: shows the
// installed version / running state, lets the operator start/stop/restart the
// service and install a version from the WINGS-N/vk-turn-proxy releases. The
// log viewer lives in VkTurnProxyLogModal; this is the control surface that the
// Vue->React migration had not ported yet.
export default function VkTurnProxyManageModal({ open, onClose, onBusy }: VkTurnProxyManageModalProps) {
  const { t } = useTranslation();
  const [modal, modalContextHolder] = Modal.useModal();
  const [versions, setVersions] = useState<string[]>([]);
  const [status, setStatus] = useState<VkTurnStatus | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [verMsg, statMsg] = await Promise.all([
        HttpUtil.get<string[]>('/panel/api/server/vk-turn-proxy/versions'),
        HttpUtil.get<VkTurnStatus>('/panel/api/server/vk-turn-proxy/status'),
      ]);
      if (verMsg?.success) setVersions(verMsg.obj || []);
      if (statMsg?.success) setStatus(statMsg.obj || null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) refresh();
  }, [open, refresh]);

  const runAction = useCallback(
    async (action: 'start' | 'stop' | 'restart') => {
      onBusy({ busy: true, tip: t('pages.index.dontRefresh') });
      try {
        await HttpUtil.post(`/panel/api/server/vk-turn-proxy/${action}`);
      } finally {
        onBusy({ busy: false });
        refresh();
      }
    },
    [onBusy, refresh, t],
  );

  const installVersion = useCallback(
    (version: string) => {
      modal.confirm({
        title: t('pages.index.vkTurnInstallDialog'),
        content: t('pages.index.vkTurnInstallDialogDesc').replace('#version#', version),
        okText: t('confirm'),
        cancelText: t('cancel'),
        onOk: async () => {
          onClose();
          onBusy({ busy: true, tip: t('pages.index.dontRefresh') });
          try {
            await HttpUtil.post(`/panel/api/server/vk-turn-proxy/install/${version}`);
          } finally {
            onBusy({ busy: false });
          }
        },
      });
    },
    [modal, onBusy, onClose, t],
  );

  const titleNode = (
    <>
      {t('pages.index.vkTurnManageTitle')}
      <ReloadOutlined className="reload-icon" onClick={refresh} />
    </>
  );

  const installed = status?.version || '';

  return (
    <Modal open={open} title={titleNode} footer={null} onCancel={onClose}>
      {modalContextHolder}
      <Spin spinning={loading}>
        {status && (
          <div className="mb-12">
            <div>
              <b>{t('pages.index.vkTurnInstalled')}:</b> {installed || '-'}
            </div>
            <div>
              <b>{t('pages.index.vkTurnRunningCount')}:</b>{' '}
              <Tag color={status.running > 0 ? 'green' : 'default'}>
                {status.running} / {status.enabled}
              </Tag>
            </div>
            {status.errorMsg && (
              <Alert type="error" showIcon className="mb-12" message={status.errorMsg} />
            )}
          </div>
        )}

        <Space className="mb-12">
          <Button onClick={() => runAction('start')}>{t('pages.index.vkTurnStart')}</Button>
          <Button onClick={() => runAction('stop')}>{t('pages.index.vkTurnStop')}</Button>
          <Button onClick={() => runAction('restart')}>{t('pages.index.vkTurnRestart')}</Button>
        </Space>

        <Alert type="info" showIcon className="mb-12" message={t('pages.index.vkTurnVersions')} />
        <div className="version-list">
          {versions.map((version, index) => (
            <div key={version} className="version-list-item">
              <Tag color={index % 2 === 0 ? 'purple' : 'green'}>{version}</Tag>
              <Radio
                checked={version === installed || version === `v${installed}`}
                onClick={() => installVersion(version)}
              />
            </div>
          ))}
        </div>
      </Spin>
    </Modal>
  );
}
