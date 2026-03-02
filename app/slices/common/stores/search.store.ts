import { defineStore } from 'pinia';
import { ProjectsService, AccessService } from '#setup/api/data/repositories/api';

interface SearchProject {
    id: string;
    name: string;
    clientName?: string;
    description?: string;
    status: string;
}

interface SearchAccess {
    id: string;
    serviceName: string;
    serviceUrl: string;
    environment: string;
    accessLevel: string;
    notes?: string;
    projectId: string;
    projectName: string;
}

const CACHE_TTL_MS = 60_000;

export const useSearchStore = defineStore('search', {
    state: () => ({
        projects: [] as SearchProject[],
        accesses: [] as SearchAccess[],
        lastFetchedAt: null as number | null,
        loading: false,
    }),

    actions: {
        async fetchSearchData(force = false) {
            const now = Date.now();
            if (!force && this.lastFetchedAt && now - this.lastFetchedAt < CACHE_TTL_MS) {
                return;
            }

            this.loading = true;
            try {
                const projectsResponse = await ProjectsService.getAllProjects(1, 100);
                this.projects = projectsResponse.data;

                const accessResults = await Promise.all(
                    projectsResponse.data.map(async (project: any) => {
                        try {
                            const accessResponse = await AccessService.getAccessByProjectId(project.id, 1, 100);
                            return accessResponse.data.map((a: any) => ({
                                ...a,
                                projectId: project.id,
                                projectName: project.name,
                            }));
                        } catch {
                            return [];
                        }
                    }),
                );

                this.accesses = accessResults.flat();
                this.lastFetchedAt = Date.now();
            } catch {
                // Silent fail — search is a convenience feature
            } finally {
                this.loading = false;
            }
        },

        invalidateCache() {
            this.lastFetchedAt = null;
        },
    },
});
