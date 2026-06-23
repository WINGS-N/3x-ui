import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Badge, Card, Col, Popover, Row, Space, Tag } from 'antd';
import { BarsOutlined, PoweroffOutlined, ReloadOutlined, ToolOutlined } from '@ant-design/icons';

import type { Status } from '@/models/status';
import './XrayStatusCard.css';

interface VkTurnProxyStatusCardProps {
  status: Status;
  isMobile: boolean;
  onStop: () => void;
  onRestart: () => void;
  onOpenLogs: () => void;
  onOpenManage: () => void;
}

const VK_TURN_STATE_KEYS: Record<string, string> = {
  running: 'pages.index.vkTurnStatusRunning',
  stop: 'pages.index.vkTurnStatusStop',
  error: 'pages.index.vkTurnStatusError',
};

// Dashboard control card for the standalone vk-turn-proxy relay, mirroring the
// Xray status card's button scheme (logs / stop / restart / manage) so the two
// read identically.
export default function VkTurnProxyStatusCard({
  status,
  isMobile,
  onStop,
  onRestart,
  onOpenLogs,
  onOpenManage,
}: VkTurnProxyStatusCardProps) {
  const { t } = useTranslation();
  const vk = status.vkTurnProxy;
  const stateText = t(VK_TURN_STATE_KEYS[vk.state] ?? 'pages.index.vkTurnStatusUnknown');

  const title = (
    <Space>
      <span>{t('pages.index.vkTurnStatus')}</span>
      {isMobile && vk.version && <Tag color="green">v{vk.version}</Tag>}
    </Space>
  );

  const errorLines = useMemo(() => (vk.errorMsg || '').split('\n'), [vk.errorMsg]);

  const extra =
    vk.state !== 'error' ? (
      <Badge status="processing" text={stateText} color={vk.color} />
    ) : (
      <Popover
        title={
          <Row align="middle" justify="space-between">
            <Col>
              <span>{t('pages.index.vkTurnStatusError')}</span>
            </Col>
            <Col>
              <BarsOutlined className="cursor-pointer" onClick={onOpenLogs} />
            </Col>
          </Row>
        }
        content={
          <>
            {errorLines.map((line, i) => (
              <span key={i} className="error-line">
                {line}
              </span>
            ))}
          </>
        }
      >
        <Badge status="processing" text={stateText} color={vk.color} />
      </Popover>
    );

  const actions = [
    <Space className="action" key="vkturnlogs" onClick={onOpenLogs}>
      <BarsOutlined />
      {!isMobile && <span>{t('pages.index.logs')}</span>}
    </Space>,
    <Space className="action" key="stop" onClick={onStop}>
      <PoweroffOutlined />
      {!isMobile && <span>{t('pages.index.vkTurnStop')}</span>}
    </Space>,
    <Space className="action" key="restart" onClick={onRestart}>
      <ReloadOutlined />
      {!isMobile && <span>{t('pages.index.vkTurnRestart')}</span>}
    </Space>,
    <Space className="action" key="manage" onClick={onOpenManage}>
      <ToolOutlined />
      {!isMobile && <span>{vk.version ? `v${vk.version}` : t('pages.index.vkTurnManage')}</span>}
    </Space>,
  ];

  return (
    <Card hoverable title={title} extra={extra} actions={actions} className="xray-status-card" />
  );
}
