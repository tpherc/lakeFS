import React, { cloneElement, forwardRef } from 'react';
import BootstrapOverlay, { OverlayChildren, OverlayProps } from 'react-bootstrap/Overlay';
import BootstrapOverlayTrigger, { OverlayTriggerProps } from 'react-bootstrap/OverlayTrigger';
import BootstrapTooltip, { TooltipProps } from 'react-bootstrap/Tooltip';

// Popper can briefly clear its styles between measurements. Keep the tooltip out of document flow.
const fallbackStyle: React.CSSProperties = { position: 'fixed', top: 0, left: 0 };

export const Tooltip = forwardRef<HTMLDivElement, TooltipProps>(({ style, ...props }, ref) => (
    <BootstrapTooltip {...props} ref={ref} style={{ ...fallbackStyle, ...style }} />
));

function renderOverlay(overlay: OverlayChildren): Exclude<OverlayChildren, React.ReactElement> {
    if (typeof overlay === 'function') return overlay;

    // Bootstrap's element-overlay path omits `show`, which Tooltip needs to hide until measured.
    return (props) =>
        cloneElement(overlay, {
            ...props,
            className: [overlay.props.className, props.className].filter(Boolean).join(' ') || undefined,
            style: { ...overlay.props.style, ...props.style },
        });
}

export const TooltipTrigger = ({ overlay, popperConfig, ...props }: OverlayTriggerProps) => (
    <BootstrapOverlayTrigger
        {...props}
        popperConfig={{ ...popperConfig, strategy: 'fixed' }}
        overlay={renderOverlay(overlay)}
    />
);

export const TooltipOverlay = forwardRef<HTMLElement, OverlayProps>(({ children, popperConfig, ...props }, ref) => (
    <BootstrapOverlay {...props} ref={ref} popperConfig={{ ...popperConfig, strategy: 'fixed' }}>
        {renderOverlay(children)}
    </BootstrapOverlay>
));
