import { useEffect, useState } from "react";
import { Routes, Route, useNavigate, useLocation, Navigate } from "react-router-dom";
import AppLayout from "@cloudscape-design/components/app-layout";
import SideNavigation from "@cloudscape-design/components/side-navigation";
import TopNavigation from "@cloudscape-design/components/top-navigation";
import { get, Me } from "./api";
import DashboardPage from "./pages/Dashboard";
import SessionsPage from "./pages/Sessions";
import ClientsPage from "./pages/Clients";
import UsersPage from "./pages/Users";
import PolicyPage from "./pages/Policy";

export default function App() {
  const nav = useNavigate();
  const loc = useLocation();
  const [me, setMe] = useState<Me>({});
  useEffect(() => {
    get<Me>("/api/me").then(setMe).catch(() => {});
  }, []);

  return (
    <>
      <div id="top-nav">
        <TopNavigation
          identity={{ href: "/", title: "usg-radius — Operations" }}
          utilities={[
            {
              type: "button",
              iconName: "user-profile",
              text: me.email || me.user || "operator",
            },
          ]}
        />
      </div>
      <AppLayout
        headerSelector="#top-nav"
        toolsHide
        navigation={
          <SideNavigation
            activeHref={loc.pathname}
            header={{ href: "/", text: "RADIUS" }}
            onFollow={(e) => {
              if (!e.detail.external) {
                e.preventDefault();
                nav(e.detail.href);
              }
            }}
            items={[
              { type: "link", text: "Dashboard", href: "/dashboard" },
              { type: "link", text: "Sessions", href: "/sessions" },
              { type: "divider" },
              { type: "link", text: "Clients (NAS)", href: "/clients" },
              { type: "link", text: "Users", href: "/users" },
              { type: "link", text: "Policy", href: "/policy" },
            ]}
          />
        }
        content={
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/sessions" element={<SessionsPage />} />
            <Route path="/clients" element={<ClientsPage />} />
            <Route path="/users" element={<UsersPage />} />
            <Route path="/policy" element={<PolicyPage />} />
          </Routes>
        }
      />
    </>
  );
}
