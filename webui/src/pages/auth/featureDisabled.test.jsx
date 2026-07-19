import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter, Outlet, Route, Routes } from 'react-router-dom';

import CredentialsPage from './credentials';
import UsersIndexPage, { UsersPage } from './users';
import PoliciesPage from './policies';

const mocks = vi.hoisted(() => ({
    loginConfig: { RBAC: 'internal' },
    push: vi.fn(),
    setActiveTab: vi.fn(),
    useAPI: vi.fn(),
    useAPIWithPagination: vi.fn(),
    user: { id: 'current-user', accessKeyId: 'AKIA_CURRENT' },
}));

vi.mock('../../lib/hooks/conf', () => ({
    useLoginConfigContext: () => mocks.loginConfig,
}));

vi.mock('../../lib/hooks/router', () => ({
    useRouter: () => ({
        query: {},
        push: mocks.push,
    }),
}));

vi.mock('../../lib/auth/authContext', () => ({
    useAuth: () => ({
        user: mocks.user,
    }),
}));

vi.mock('../../lib/hooks/api', () => ({
    useAPI: (...args) => mocks.useAPI(...args),
    useAPIWithPagination: (...args) => mocks.useAPIWithPagination(...args),
}));

vi.mock('../../lib/components/controls', () => ({
    ActionGroup: ({ children }) => <div>{children}</div>,
    ActionsBar: ({ children }) => <div>{children}</div>,
    AlertError: ({ error }) => <div>{String(error)}</div>,
    Checkbox: () => <input type="checkbox" readOnly />,
    DataTable: () => <table />,
    FormattedDate: ({ dateValue }) => <span>{dateValue}</span>,
    Loading: () => <div>Loading...</div>,
    RefreshButton: () => <button type="button">Refresh</button>,
    SearchInput: ({ placeholder }) => <input placeholder={placeholder} readOnly />,
    Warning: ({ children }) => <div>{children}</div>,
    useDebouncedState: (value) => [value, vi.fn()],
}));

vi.mock('../../lib/components/modals', () => ({
    ConfirmationButton: ({ children, disabled = false }) => (
        <button type="button" disabled={disabled}>
            {children}
        </button>
    ),
}));

vi.mock('../../lib/components/pagination', () => ({
    Paginator: () => <div />,
}));

vi.mock('../../lib/components/nav', () => ({
    Link: ({ children }) => <a href="/">{children}</a>,
}));

vi.mock('../../lib/components/auth/credentials', () => ({
    CredentialsShowModal: () => <div />,
    CredentialsTable: () => <div />,
}));

vi.mock('../../lib/components/auth/forms', () => ({
    EntityActionModal: () => <div />,
}));

vi.mock('../../lib/components/auth/users', () => ({
    allUsersFromLakeFS: vi.fn(() => Promise.resolve([])),
}));

vi.mock('../../lib/components/policy', () => ({
    PolicyEditor: () => <div />,
}));

vi.mock('react-bootstrap/Button', () => ({
    default: ({ children, hidden = false, disabled = false, onClick }) =>
        hidden ? null : (
            <button type="button" disabled={disabled} onClick={onClick}>
                {children}
            </button>
        ),
}));

vi.mock('../../lib/api', () => ({
    auth: {
        createCredentials: vi.fn(),
        createGroup: vi.fn(),
        createPolicy: vi.fn(),
        createUser: vi.fn(),
        deleteGroups: vi.fn(),
        deletePolicies: vi.fn(),
        deleteUsers: vi.fn(),
        getAuthCapabilities: vi.fn(),
        listCredentials: vi.fn(),
        listGroups: vi.fn(),
        listPolicies: vi.fn(),
        listUsers: vi.fn(),
        putACL: vi.fn(),
    },
}));

const ParentOutlet = ({ context }) => <Outlet context={context} />;

const renderAuthPage = (page) => {
    render(
        <MemoryRouter initialEntries={['/']}>
            <Routes>
                <Route element={<ParentOutlet context={[mocks.setActiveTab]} />}>
                    <Route path="/" element={page} />
                </Route>
            </Routes>
        </MemoryRouter>,
    );
};

const renderUsersPage = () => {
    render(
        <MemoryRouter initialEntries={['/']}>
            <Routes>
                <Route element={<ParentOutlet context={[mocks.setActiveTab]} />}>
                    <Route path="/" element={<UsersIndexPage />}>
                        <Route index element={<UsersPage />} />
                    </Route>
                </Route>
            </Routes>
        </MemoryRouter>,
    );
};

describe('auth pages with disabled RBAC', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mocks.loginConfig.RBAC = 'internal';
        mocks.useAPI.mockReturnValue({ response: [], error: null, loading: false });
        mocks.useAPIWithPagination.mockReturnValue({ results: [], error: null, loading: false, nextPage: null });
    });

    it('shows a minimal disabled state for credentials only when RBAC is none', () => {
        mocks.loginConfig.RBAC = 'none';
        renderAuthPage(<CredentialsPage />);
        expect(screen.getByText('Feature disabled')).toBeInTheDocument();

        cleanup();
        mocks.loginConfig.RBAC = 'internal';
        renderAuthPage(<CredentialsPage />);
        expect(screen.queryByText('Feature disabled')).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Create Access Key' })).toBeInTheDocument();
    });

    it('shows a minimal disabled state for users only when RBAC is none', () => {
        mocks.loginConfig.RBAC = 'none';
        renderUsersPage();
        expect(screen.getByText('Feature disabled')).toBeInTheDocument();

        cleanup();
        mocks.loginConfig.RBAC = 'internal';
        renderUsersPage();
        expect(screen.queryByText('Feature disabled')).not.toBeInTheDocument();
        expect(screen.getByPlaceholderText('Find a User...')).toBeInTheDocument();
    });

    it('shows a minimal disabled state for policies only when RBAC is none', () => {
        mocks.loginConfig.RBAC = 'none';
        renderAuthPage(<PoliciesPage />);
        expect(screen.getByText('Feature disabled')).toBeInTheDocument();

        cleanup();
        mocks.loginConfig.RBAC = 'internal';
        renderAuthPage(<PoliciesPage />);
        expect(screen.queryByText('Feature disabled')).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Create Policy' })).toBeInTheDocument();
    });
});
