import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import LoginPage, { getLoginIntent, withNext } from './login';

const useAPIMock = vi.fn();
const refreshUserMock = vi.fn();

vi.mock('../../lib/hooks/api', () => ({
    useAPI: (...args: unknown[]) => useAPIMock(...args),
}));

vi.mock('../../lib/components/controls', () => ({
    AlertError: ({ error }: { error: unknown }) => <div>{String(error)}</div>,
    Loading: () => <div>Loading...</div>,
}));

vi.mock('react-bootstrap/Button', () => ({
    default: ({
        children,
        type = 'button',
        onClick,
    }: {
        children: React.ReactNode;
        type?: 'button' | 'submit';
        onClick?: () => void;
    }) => (
        <button type={type} onClick={onClick}>
            {children}
        </button>
    ),
}));

vi.mock('react-bootstrap/Card', () => {
    const Card = ({ children }: { children: React.ReactNode }) => <div>{children}</div>;
    Card.Header = ({ children }: { children: React.ReactNode }) => <div>{children}</div>;
    Card.Body = ({ children }: { children: React.ReactNode }) => <div>{children}</div>;
    return { default: Card };
});

vi.mock('react-bootstrap/Form', () => {
    const Form = ({
        children,
        onSubmit,
    }: {
        children: React.ReactNode;
        onSubmit?: (event: React.FormEvent<HTMLFormElement>) => void;
    }) => <form onSubmit={onSubmit}>{children}</form>;
    Form.Group = ({ children }: { children: React.ReactNode }) => <div>{children}</div>;
    Form.Control = (props: React.InputHTMLAttributes<HTMLInputElement>) => <input {...props} />;
    return { default: Form };
});

vi.mock('../../lib/auth/authContext', () => ({
    LAKEFS_POST_LOGIN_NEXT: 'LAKEFS_POST_LOGIN_NEXT',
    useAuth: () => ({
        refreshUser: refreshUserMock,
    }),
}));

vi.mock('../../lib/api', () => ({
    auth: {
        login: vi.fn(),
    },
    setup: {
        getState: vi.fn(),
    },
    SETUP_STATE_INITIALIZED: 'initialized',
    AuthenticationError: class AuthenticationError extends Error {},
    ClientError: class ClientError extends Error {},
    ServerError: class ServerError extends Error {},
}));

const defaultSetupResponse = {
    state: 'initialized',
    login_config: {
        login_url: '/oidc/login',
        login_url_method: 'select',
        login_cookie_names: [],
        logout_url: '/logout',
    },
};

describe('login page helpers', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        window.sessionStorage.clear();
        useAPIMock.mockReturnValue({
            response: defaultSetupResponse,
            error: null,
            loading: false,
        });
        refreshUserMock.mockResolvedValue(undefined);
    });

    it('adds normalized next to login urls', () => {
        expect(withNext('/oidc/login', '/repositories/demo')).toContain('next=%2Frepositories%2Fdemo');
    });

    it('strips redirected from the query string when present', () => {
        const intent = getLoginIntent({
            pathname: '/auth/login',
            search: '?redirected=true&next=/repositories/demo',
            hash: '',
            state: null,
        } as never);

        expect(intent.redirected).toBe(true);
        expect(intent.next).toBe('/repositories/demo');
        expect(intent.cleanUrl).toBe('/auth/login?next=%2Frepositories%2Fdemo');
    });
});

describe('LoginPage', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        window.sessionStorage.clear();
        useAPIMock.mockReturnValue({
            response: defaultSetupResponse,
            error: null,
            loading: false,
        });
        refreshUserMock.mockResolvedValue(undefined);
    });

    it('shows an explicit SSO action for select mode', () => {
        render(
            <MemoryRouter initialEntries={['/auth/login']}>
                <LoginPage />
            </MemoryRouter>,
        );

        expect(screen.getByRole('button', { name: 'Login with SSO' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Login' })).toBeInTheDocument();
    });
});
