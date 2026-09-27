import React from 'react';

import { Tooltip, TooltipTrigger } from '../tooltips';
import { CheckCircleFillIcon, StopwatchIcon, XCircleFillIcon, SkipIcon } from '@primer/octicons-react';

export const ActionStatusIcon = ({ status, className = null }) => {
    let icon = <StopwatchIcon fill="orange" verticalAlign="middle" />;
    if (status === 'completed') {
        icon = <CheckCircleFillIcon fill="green" verticalAlign="middle" />;
    } else if (status === 'failed') {
        icon = <XCircleFillIcon fill="red" verticalAlign="middle" />;
    } else if (status === 'skipped') {
        icon = <SkipIcon fill="yellow" verticalAlign="middle" />;
    }
    // otherwise, probably still running
    return (
        <TooltipTrigger placement="bottom" overlay={<Tooltip>{status}</Tooltip>}>
            <span className={className}>{icon}</span>
        </TooltipTrigger>
    );
};
