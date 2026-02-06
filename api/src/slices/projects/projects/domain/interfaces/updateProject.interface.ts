import { ICreateProject } from "./createProject.interface";

export interface IUpdateProject extends ICreateProject {
    id: string;
}