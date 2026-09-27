import React, { FC } from 'react';
import { Outlet } from 'react-router-dom';
import { ConfigProvider } from '../hooks/configProvider';
import TopNav from './navbar';
import { AUTH_STATUS, useAuth } from '../auth/authContext';

const Layout: FC = () => {
    const { status } = useAuth();
    const showTopNav = status === AUTH_STATUS.AUTHENTICATED;

    return (
        <ConfigProvider>
            <div className="app-layout">
                {showTopNav && <TopNav />}
                <div className="main-app">
                    <Outlet />
                </div>
            </div>
        </ConfigProvider>
    );
};

export default Layout;
