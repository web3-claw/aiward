use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::{config, registry, workspace};

#[derive(Debug, Clone, Default)]
pub struct TargetSelector {
    pub project: Option<String>,
    pub app: Option<String>,
    pub all: bool,
}

impl TargetSelector {
    pub fn one(project: Option<String>, app: Option<String>) -> Self {
        Self {
            project,
            app,
            all: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkspaceTarget {
    pub name: String,
    pub path: PathBuf,
    pub vault: PathBuf,
    pub workspace_root: Option<PathBuf>,
    pub workspace_name: Option<String>,
    pub app_slug: Option<String>,
    pub package_name: Option<String>,
}

impl WorkspaceTarget {
    pub fn resolved_project(&self) -> registry::ResolvedProject {
        registry::ResolvedProject {
            name: self.name.clone(),
            path: self.path.clone(),
            vault: self.vault.clone(),
        }
    }

    pub fn is_workspace_child(&self) -> bool {
        self.workspace_root.is_some()
    }
}

pub fn resolve_one(selector: &TargetSelector, cwd: &Path) -> Result<WorkspaceTarget> {
    if selector.all {
        anyhow::bail!("--all cannot be used where exactly one Ward project is required");
    }
    if selector.project.is_some() && selector.app.is_some() {
        anyhow::bail!("choose either --project or --app, not both");
    }
    if let Some(project) = selector.project.as_deref() {
        return explicit_project(project, cwd);
    }
    if let Some(app) = selector.app.as_deref() {
        return explicit_app(app, cwd);
    }
    implicit_one(cwd)
}

pub fn resolve_one_with_passphrase(
    selector: &TargetSelector,
    cwd: &Path,
    passphrase: &str,
) -> Result<WorkspaceTarget> {
    let mut target = resolve_one(selector, cwd)?;
    refresh_vault_with_passphrase(&mut target, passphrase);
    Ok(target)
}

pub fn resolve_many(selector: &TargetSelector, cwd: &Path) -> Result<Vec<WorkspaceTarget>> {
    if selector.project.is_some() && selector.app.is_some() {
        anyhow::bail!("choose either --project or --app, not both");
    }
    if !selector.all {
        return resolve_one(selector, cwd).map(|target| vec![target]);
    }
    if selector.project.is_some() || selector.app.is_some() {
        anyhow::bail!("--all cannot be combined with --project or --app");
    }
    let discovery = workspace::discover_containing(cwd)?
        .context("--all requires running inside a Ward workspace")?;
    let targets = configured_workspace_targets(&discovery)?;
    if targets.is_empty() {
        anyhow::bail!("workspace has no configured Ward app projects");
    }
    Ok(targets)
}

pub fn resolve_many_with_passphrase(
    selector: &TargetSelector,
    cwd: &Path,
    passphrase: &str,
) -> Result<Vec<WorkspaceTarget>> {
    let mut targets = resolve_many(selector, cwd)?;
    for target in &mut targets {
        refresh_vault_with_passphrase(target, passphrase);
    }
    Ok(targets)
}

pub fn configured_workspace_targets(
    discovery: &workspace::WorkspaceDiscovery,
) -> Result<Vec<WorkspaceTarget>> {
    let registry = registry::list_projects().unwrap_or_default();
    let mut targets = Vec::new();
    for package in discovery.app_candidates() {
        let Ok(cfg) = config::read_project_config(&package.path) else {
            continue;
        };
        let registered = registry.projects.get(&cfg.project);
        let vault = registered
            .map(|registered| registered.vault.clone())
            .unwrap_or_else(|| config::resolve_vault_path(&package.path, &cfg));
        targets.push(WorkspaceTarget {
            name: cfg.project,
            path: package.path.clone(),
            vault,
            workspace_root: Some(discovery.root.clone()),
            workspace_name: Some(discovery.workspace_name.clone()),
            app_slug: Some(package.slug.clone()),
            package_name: package.name.clone(),
        });
    }
    Ok(targets)
}

pub fn find_workspace_package_for_project<'a>(
    discovery: &'a workspace::WorkspaceDiscovery,
    project: &str,
) -> Option<&'a workspace::WorkspacePackage> {
    discovery.app_candidates().find(|package| {
        package.project_name == project
            || config::read_project_config(&package.path)
                .map(|cfg| cfg.project == project)
                .unwrap_or(false)
    })
}

pub fn register_workspace_metadata(
    project: &str,
    discovery: &workspace::WorkspaceDiscovery,
    package: &workspace::WorkspacePackage,
) -> Result<()> {
    registry::update_project_workspace_metadata(
        project,
        Some(discovery.root.clone()),
        Some(discovery.workspace_name.clone()),
        Some(package.slug.clone()),
        Some(discovery.workspace_name.clone()),
    )
}

pub fn target_suggestions(targets: &[WorkspaceTarget]) -> String {
    targets
        .iter()
        .map(|target| {
            let app = target.app_slug.as_deref().unwrap_or(&target.name);
            format!("{app} ({})", target.name)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn explicit_project(project: &str, cwd: &Path) -> Result<WorkspaceTarget> {
    let resolved = registry::resolve_project(Some(project), cwd)
        .context(format!("project {project} is not registered"))?;
    let mut target = target_from_resolved(resolved);
    attach_registry_metadata(&mut target);
    attach_workspace_metadata(&mut target)?;
    Ok(target)
}

fn explicit_app(app: &str, cwd: &Path) -> Result<WorkspaceTarget> {
    let discovery = workspace::discover_containing(cwd)?
        .context("--app requires running inside a Ward workspace")?;
    let package = discovery
        .app_candidates()
        .find(|package| package.matches(app))
        .with_context(|| format!("workspace app {app} was not found"))?;
    target_from_package(&discovery, package).with_context(|| {
        format!("workspace app {app} is not configured; run ward setup --workspace --app {app}")
    })
}

fn implicit_one(cwd: &Path) -> Result<WorkspaceTarget> {
    if let Some(project_root) = config::find_project_root(cwd) {
        let resolved = registry::resolve_project(None, &project_root)?;
        let mut target = target_from_resolved(resolved);
        attach_registry_metadata(&mut target);
        attach_workspace_metadata(&mut target)?;
        return Ok(target);
    }

    if let Some(discovery) = workspace::discover_containing(cwd)? {
        let targets = configured_workspace_targets(&discovery)?;
        return match targets.len() {
            0 => anyhow::bail!("workspace has no configured Ward app projects; run ward setup --workspace"),
            1 => Ok(targets.into_iter().next().expect("one target exists")),
            _ => anyhow::bail!(
                "workspace root has multiple Ward app projects; human mode is per app, so choose one with --app <app> or --project <project>, or run ward human inside each app folder: {}",
                target_suggestions(&targets)
            ),
        };
    }

    let resolved = registry::resolve_project(None, cwd)?;
    let mut target = target_from_resolved(resolved);
    attach_registry_metadata(&mut target);
    Ok(target)
}

fn target_from_package(
    discovery: &workspace::WorkspaceDiscovery,
    package: &workspace::WorkspacePackage,
) -> Result<WorkspaceTarget> {
    let cfg = config::read_project_config(&package.path)?;
    let registry = registry::list_projects().unwrap_or_default();
    let vault = registry
        .projects
        .get(&cfg.project)
        .map(|registered| registered.vault.clone())
        .unwrap_or_else(|| config::resolve_vault_path(&package.path, &cfg));
    Ok(WorkspaceTarget {
        name: cfg.project,
        path: package.path.clone(),
        vault,
        workspace_root: Some(discovery.root.clone()),
        workspace_name: Some(discovery.workspace_name.clone()),
        app_slug: Some(package.slug.clone()),
        package_name: package.name.clone(),
    })
}

fn target_from_resolved(resolved: registry::ResolvedProject) -> WorkspaceTarget {
    WorkspaceTarget {
        name: resolved.name,
        path: resolved.path,
        vault: resolved.vault,
        workspace_root: None,
        workspace_name: None,
        app_slug: None,
        package_name: None,
    }
}

fn attach_registry_metadata(target: &mut WorkspaceTarget) {
    let Ok(registry) = registry::list_projects() else {
        return;
    };
    let Some(registered) = registry.projects.get(&target.name) else {
        return;
    };
    target.workspace_root = registered.workspace_root.clone();
    target.workspace_name = registered.workspace_name.clone();
    target.app_slug = registered.app_slug.clone();
}

fn attach_workspace_metadata(target: &mut WorkspaceTarget) -> Result<()> {
    if target.workspace_root.is_some() {
        return Ok(());
    }
    let Some(discovery) = workspace::discover_containing(&target.path)? else {
        return Ok(());
    };
    if let Some(package) = find_workspace_package_for_project(&discovery, &target.name) {
        target.workspace_root = Some(discovery.root.clone());
        target.workspace_name = Some(discovery.workspace_name.clone());
        target.app_slug = Some(package.slug.clone());
        target.package_name = package.name.clone();
    }
    Ok(())
}

fn refresh_vault_with_passphrase(target: &mut WorkspaceTarget, passphrase: &str) {
    if let Ok(config) = config::read_project_config(&target.path) {
        if config.project == target.name {
            target.vault =
                config::resolve_vault_path_with_passphrase(&target.path, &config, passphrase);
        }
    }
}
