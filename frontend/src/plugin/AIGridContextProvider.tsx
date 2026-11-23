import { useCallback, useEffect, useMemo, useState } from 'react';
import { BackendProvider } from '../api/connect/BackendProvider';
import { HttpConsoleService } from '../api/HttpConsoleService';
import type { User } from '../api/types';
import { ConsoleSessionContext } from '../context/useConsoleSession';

const PLUGIN_API_PREFIX = '/api/plugin/ai-grid-provider-console';

/** Provides AI Grid's session and backend contexts to all contributed pages. */
const AIGridContextProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const service = useMemo(() => new HttpConsoleService(undefined, `${PLUGIN_API_PREFIX}/api/v1`), []);
  const [user, setUser] = useState<User>();
  const [userLoaded, setUserLoaded] = useState(false);
  const [userError, setUserError] = useState<Error>();

  const loadUser = useCallback(async () => {
    try {
      setUser(await service.getUser());
      setUserError(undefined);
    } catch (cause) {
      setUserError(cause instanceof Error ? cause : new Error('Unable to load the signed-in user.'));
    } finally {
      setUserLoaded(true);
    }
  }, [service]);

  useEffect(() => {
    void loadUser();
  }, [loadUser]);

  const checkSession = useCallback(() => {
    void loadUser();
  }, [loadUser]);
  const session = useMemo(
    () => ({ user, userLoaded, userError, checkSession }),
    [user, userLoaded, userError, checkSession],
  );

  return (
    <ConsoleSessionContext.Provider value={session}>
      <BackendProvider checkSession={checkSession} baseUrl={`${window.location.origin}${PLUGIN_API_PREFIX}`}>
        {children}
      </BackendProvider>
    </ConsoleSessionContext.Provider>
  );
};

export default AIGridContextProvider;
