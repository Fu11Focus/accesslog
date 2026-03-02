import { paths } from '#common/paths';

export interface BreadcrumbItem {
    label: string;
    to?: string;
}

export function useBreadcrumbs() {
    const route = useRoute();
    const { t } = useI18n();

    const breadcrumbs = computed<BreadcrumbItem[]>(() => {
        const items: BreadcrumbItem[] = [];
        const path = route.path;

        // Home is always first (except on home page itself)
        if (path !== '/') {
            items.push({ label: t('breadcrumbs.home'), to: paths.home });
        }

        // /projects
        if (path.startsWith('/projects')) {
            items.push(
                path === '/projects'
                    ? { label: t('breadcrumbs.projects') }
                    : { label: t('breadcrumbs.projects'), to: paths.projects },
            );
        }

        // /projects/create
        if (path === '/projects/create') {
            items.push({ label: t('breadcrumbs.createProject') });
        }

        // /projects/:id/edit
        if (route.name === 'projects-id-edit') {
            const projectName = route.meta.projectName as string | undefined;
            items.push({ label: projectName || t('breadcrumbs.editProject') });
        }

        // /contact
        if (path === '/contact') {
            items.push({ label: t('breadcrumbs.contact') });
        }

        // /terms
        if (path === '/terms') {
            items.push({ label: t('breadcrumbs.terms') });
        }

        // /private-policy
        if (path === '/private-policy') {
            items.push({ label: t('breadcrumbs.policy') });
        }

        // /settings
        if (path === '/settings') {
            items.push({ label: t('breadcrumbs.settings') });
        }

        return items;
    });

    return { breadcrumbs };
}
