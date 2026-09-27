import React, { createRef } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Tooltip, TooltipOverlay, TooltipTrigger } from './tooltips';

describe('shared tooltips', () => {
    afterEach(() => vi.restoreAllMocks());

    it('preserves rich element content, presentation, placement, and trigger behavior', async () => {
        const triggerRef = createRef<HTMLButtonElement>();
        const onClick = vi.fn();
        render(
            <TooltipTrigger
                placement="left"
                overlay={
                    <Tooltip id="change-summary" className="summary-tooltip" style={{ color: 'rgb(12, 34, 56)' }}>
                        <strong>3 added objects</strong>
                        <span> (120 bytes)</span>
                    </Tooltip>
                }
            >
                <button ref={triggerRef} onClick={onClick}>
                    Summary
                </button>
            </TooltipTrigger>,
        );
        const button = screen.getByRole('button', { name: 'Summary' });
        expect(triggerRef.current).toBe(button);
        fireEvent.focus(button);

        const tooltip = await screen.findByRole('tooltip');
        expect(tooltip).toHaveAttribute('id', 'change-summary');
        expect(tooltip).toHaveClass('summary-tooltip');
        expect(tooltip).toHaveStyle({ color: 'rgb(12, 34, 56)' });
        expect(tooltip.querySelector('strong')).toHaveTextContent('3 added objects');
        expect(tooltip).toHaveTextContent('(120 bytes)');
        await waitFor(() => {
            expect(tooltip).toHaveAttribute('data-popper-placement', 'left');
            expect(tooltip.style.position).toBe('fixed');
            expect(tooltip.style.transform).not.toBe('');
            expect(tooltip.querySelector<HTMLElement>('.tooltip-arrow')?.style.position).toBe('absolute');
            expect(button).toHaveAttribute('aria-describedby', 'change-summary');
        });

        fireEvent.click(button);
        expect(onClick).toHaveBeenCalledOnce();
        fireEvent.blur(button);
        await waitFor(() => expect(screen.queryByRole('tooltip')).not.toBeInTheDocument());
    });

    it('preserves the hidden flag used by row actions without a tooltip', async () => {
        const control = (hidden: boolean) => (
            <TooltipTrigger show placement="bottom" overlay={<Tooltip hidden={hidden}>Row action</Tooltip>}>
                <button>Action</button>
            </TooltipTrigger>
        );
        const { rerender } = render(control(true));
        expect(await screen.findByRole('tooltip', { hidden: true })).toHaveAttribute('hidden');
        expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();

        rerender(control(false));
        expect(await screen.findByRole('tooltip')).not.toHaveAttribute('hidden');
    });

    it('positions controlled function overlays and forwards their DOM ref and updater', async () => {
        const target = createRef<HTMLButtonElement>();
        const overlayRef = createRef<HTMLElement>();
        let scheduleUpdate: (() => void) | undefined;
        const initialStyles: Array<{ position: string; opacity: string }> = [];
        const appendChild = document.body.appendChild.bind(document.body);
        vi.spyOn(document.body, 'appendChild').mockImplementation((node) => {
            if (node instanceof HTMLElement && node.getAttribute('role') === 'tooltip') {
                initialStyles.push({ position: node.style.position, opacity: node.style.opacity });
            }
            return appendChild(node);
        });
        const control = (show: boolean) => (
            <>
                <button ref={target}>Copy</button>
                <TooltipOverlay target={target} ref={overlayRef} show={show} placement="bottom">
                    {(props) => {
                        scheduleUpdate = props.popper.scheduleUpdate;
                        return <Tooltip {...props}>Copy commit ID</Tooltip>;
                    }}
                </TooltipOverlay>
            </>
        );
        const { rerender } = render(control(false));
        expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();

        rerender(control(true));
        const tooltip = await screen.findByRole('tooltip');
        expect(initialStyles).toEqual([{ position: 'fixed', opacity: '0' }]);
        expect(overlayRef.current).toBe(tooltip);
        await waitFor(() => {
            expect(tooltip.style.position).toBe('fixed');
            expect(tooltip.style.transform).not.toBe('');
            expect(tooltip.style.opacity).toBe('');
            expect(scheduleUpdate).toBeTypeOf('function');
        });
        await act(async () => scheduleUpdate?.());
        expect(tooltip).toHaveTextContent('Copy commit ID');

        rerender(control(false));
        await waitFor(() => expect(screen.queryByRole('tooltip')).not.toBeInTheDocument());
    });
});
