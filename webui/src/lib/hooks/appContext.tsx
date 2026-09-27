import React, { createContext, useLayoutEffect, useReducer } from 'react';

type AppContextType = {
    settings: AppContext;
};

type AppContext = {
    darkMode: boolean;
};

const localStorageKeys = {
    darkMode: 'darkMode',
};

enum AppActionType {
    setDarkMode = 'setDarkMode',
}

interface Action {
    type: AppActionType;
    value: boolean;
}

const initialLocalSettings: AppContext = {
    darkMode: document.documentElement.getAttribute('data-bs-theme') === 'dark',
};

const initialAppContext: AppContextType = {
    settings: initialLocalSettings,
};

const appContextReducer = (state: AppContextType, action: Action) => {
    switch (action.type) {
        case AppActionType.setDarkMode:
            return { ...state, settings: { ...state.settings, darkMode: action.value } };
        default:
            return state;
    }
};

type ContextType = {
    state: AppContextType;
    dispatch: React.Dispatch<Action>;
};

const AppContext = createContext<ContextType>({
    state: initialAppContext,
    dispatch: () => null,
});

// @ts-expect-error - it doesn't like the "children" prop
const WithAppContext: React.FC = ({ children }) => {
    const [state, dispatch] = useReducer(appContextReducer, initialAppContext);

    useLayoutEffect(() => {
        document.documentElement.setAttribute('data-bs-theme', state.settings.darkMode ? 'dark' : 'light');
        try {
            window.localStorage.setItem(localStorageKeys.darkMode, String(state.settings.darkMode));
        } catch {
            // Theme changes still work for this session when storage is unavailable.
        }
    }, [state.settings.darkMode]);

    return <AppContext.Provider value={{ state, dispatch }}>{children}</AppContext.Provider>;
};

export { WithAppContext, AppContext, AppActionType };
