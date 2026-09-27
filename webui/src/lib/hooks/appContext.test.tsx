import React, { useContext } from 'react';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { runInNewContext } from 'node:vm';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const themeScriptPath = resolve('pub/theme.js');
const themeScript = readFileSync(themeScriptPath, 'utf8');
const indexHtml = readFileSync('index.html', 'utf8');

const bootstrapTheme = () => {
    runInNewContext(themeScript, { window, document }, { filename: themeScriptPath });
};

const renderThemeToggle = async () => {
    const { AppContext, AppActionType, WithAppContext } = await import('./appContext');
    const ThemeToggle = () => {
        const { state, dispatch } = useContext(AppContext);
        return (
            <button
                onClick={() => dispatch({ type: AppActionType.setDarkMode, value: !state.settings.darkMode })}
                aria-pressed={state.settings.darkMode}
            >
                Dark mode
            </button>
        );
    };
    render(<ThemeToggle />, { wrapper: WithAppContext });
    return screen.getByRole('button', { name: 'Dark mode' });
};

beforeEach(() => {
    vi.resetModules();
    window.localStorage.clear();
    document.documentElement.removeAttribute('data-bs-theme');
});

afterEach(() => {
    vi.restoreAllMocks();
    window.localStorage.clear();
    document.documentElement.removeAttribute('data-bs-theme');
});

describe('theme bootstrap', () => {
    it('loads synchronously in the document head before the application', () => {
        const page = new DOMParser().parseFromString(indexHtml, 'text/html');
        const script = page.querySelector('head script[src="/theme.js"]');
        expect(script).not.toBeNull();
        expect(script).not.toHaveAttribute('async');
        expect(script).not.toHaveAttribute('defer');
        expect(script).not.toHaveAttribute('type', 'module');
    });

    it.each([
        ['true', 'dark'],
        ['false', 'light'],
        [null, 'light'],
        ['invalid', 'light'],
    ])('applies %s from storage as the %s theme before React mounts', (savedTheme, expectedTheme) => {
        if (savedTheme !== null) window.localStorage.setItem('darkMode', savedTheme);

        bootstrapTheme();

        expect(document.documentElement).toHaveAttribute('data-bs-theme', expectedTheme);
    });

    it('defaults to light when accessing storage throws', () => {
        vi.spyOn(window, 'localStorage', 'get').mockImplementation(() => {
            throw new Error('Storage is unavailable');
        });

        expect(bootstrapTheme).not.toThrow();
        expect(document.documentElement).toHaveAttribute('data-bs-theme', 'light');
    });
});

describe('application theme', () => {
    it.each([false, true])('preserves the bootstrapped darkMode=%s and persists toggles', async (darkMode) => {
        const user = userEvent.setup();
        window.localStorage.setItem('darkMode', String(darkMode));
        bootstrapTheme();

        const toggle = await renderThemeToggle();

        expect(toggle).toHaveAttribute('aria-pressed', String(darkMode));
        expect(document.documentElement).toHaveAttribute('data-bs-theme', darkMode ? 'dark' : 'light');

        await user.click(toggle);

        expect(toggle).toHaveAttribute('aria-pressed', String(!darkMode));
        expect(document.documentElement).toHaveAttribute('data-bs-theme', darkMode ? 'light' : 'dark');
        expect(window.localStorage.getItem('darkMode')).toBe(String(!darkMode));
    });

    it('keeps theme toggles working when storage writes throw', async () => {
        const user = userEvent.setup();
        window.localStorage.setItem('darkMode', 'true');
        bootstrapTheme();
        vi.spyOn(window.localStorage, 'setItem').mockImplementation(() => {
            throw new Error('Storage writes are unavailable');
        });

        const toggle = await renderThemeToggle();
        expect(toggle).toHaveAttribute('aria-pressed', 'true');

        await user.click(toggle);
        expect(toggle).toHaveAttribute('aria-pressed', 'false');
        expect(document.documentElement).toHaveAttribute('data-bs-theme', 'light');

        await user.click(toggle);
        expect(toggle).toHaveAttribute('aria-pressed', 'true');
        expect(document.documentElement).toHaveAttribute('data-bs-theme', 'dark');
    });

    it('mounts and changes theme when storage access is unavailable', async () => {
        const user = userEvent.setup();
        vi.spyOn(window, 'localStorage', 'get').mockImplementation(() => {
            throw new Error('Storage is unavailable');
        });
        bootstrapTheme();

        const toggle = await renderThemeToggle();
        expect(toggle).toHaveAttribute('aria-pressed', 'false');

        await user.click(toggle);

        expect(toggle).toHaveAttribute('aria-pressed', 'true');
        expect(document.documentElement).toHaveAttribute('data-bs-theme', 'dark');
    });
});
