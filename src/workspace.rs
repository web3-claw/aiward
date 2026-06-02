use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDiscovery {
    pub root: PathBuf,
    pub workspace_name: String,
    pub package_manager: Option<String>,
    pub turborepo: bool,
    pub packages: Vec<WorkspacePackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspacePackage {
    pub name: Option<String>,
    pub slug: String,
    pub project_name: String,
    pub relative_path: PathBuf,
    pub path: PathBuf,
    pub package_kind: WorkspacePackageKind,
    pub app_candidate: bool,
    pub env_status: WorkspaceEnvStatus,
    pub setup_status: WorkspaceSetupStatus,
    pub env_example_keys: Vec<String>,
    pub scripts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum WorkspacePackageKind {
    App,
    Package,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum WorkspaceEnvStatus {
    Present,
    ExampleOnly,
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum WorkspaceSetupStatus {
    Configured,
    NeedsEnv,
    NotConfigured,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageJson {
    name: Option<String>,
    #[serde(rename = "packageManager")]
    package_manager: Option<String>,
    workspaces: Option<WorkspacesField>,
    #[serde(default)]
    scripts: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum WorkspacesField {
    List(Vec<String>),
    Object { packages: Vec<String> },
}

pub fn discover(root: &Path) -> Result<Option<WorkspaceDiscovery>> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let root_package = read_package_json(&root).unwrap_or(PackageJson {
        name: None,
        package_manager: None,
        workspaces: None,
        scripts: BTreeMap::new(),
    });
    let mut globs = workspace_globs_from_pnpm(&root)?;
    globs.extend(workspace_globs_from_package_json(&root_package));
    let turborepo = root.join("turbo.json").is_file();

    if globs.is_empty() && turborepo {
        if root.join("apps").is_dir() {
            globs.push("apps/*".to_string());
        }
        if root.join("packages").is_dir() {
            globs.push("packages/*".to_string());
        }
    }
    if globs.is_empty() {
        return Ok(None);
    }

    let workspace_name = workspace_name(&root, root_package.name.as_deref());
    let package_manager = root_package
        .package_manager
        .as_deref()
        .and_then(package_manager_name);
    let mut packages = workspace_packages(&root, &workspace_name, &globs)?;
    packages.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    Ok(Some(WorkspaceDiscovery {
        root,
        workspace_name,
        package_manager,
        turborepo,
        packages,
    }))
}

pub fn find_workspace_root(cwd: &Path) -> Result<Option<PathBuf>> {
    let cwd = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    for dir in cwd.ancestors() {
        if discover(dir)?.is_some() {
            return Ok(Some(dir.to_path_buf()));
        }
    }
    Ok(None)
}

pub fn discover_containing(cwd: &Path) -> Result<Option<WorkspaceDiscovery>> {
    let Some(root) = find_workspace_root(cwd)? else {
        return Ok(None);
    };
    discover(&root)
}

impl WorkspaceDiscovery {
    pub fn app_candidates(&self) -> impl Iterator<Item = &WorkspacePackage> {
        self.packages.iter().filter(|package| package.app_candidate)
    }

    pub fn selected_apps<'a>(
        &'a self,
        requested: &[String],
        all: bool,
    ) -> Result<Vec<&'a WorkspacePackage>> {
        if all {
            return Ok(self.app_candidates().collect());
        }
        let mut selected = Vec::new();
        for app in requested {
            let Some(package) = self.app_candidates().find(|package| package.matches(app)) else {
                anyhow::bail!("workspace app {app} was not found");
            };
            selected.push(package);
        }
        Ok(selected)
    }
}

impl WorkspacePackage {
    pub fn can_setup(&self) -> bool {
        self.app_candidate
            && self.setup_status != WorkspaceSetupStatus::Configured
            && self.env_status == WorkspaceEnvStatus::Present
    }

    pub fn matches(&self, value: &str) -> bool {
        self.slug == value
            || self.project_name == value
            || self.name.as_deref() == Some(value)
            || self.relative_path.to_string_lossy() == value
    }
}

fn workspace_packages(
    root: &Path,
    workspace_name: &str,
    globs: &[String],
) -> Result<Vec<WorkspacePackage>> {
    let mut package_dirs = BTreeSet::new();
    for pattern in globs {
        let pattern = pattern.trim();
        if pattern.is_empty() || pattern.starts_with('!') {
            continue;
        }
        let absolute_pattern = root.join(pattern).to_string_lossy().to_string();
        for entry in glob::glob(&absolute_pattern)
            .with_context(|| format!("failed to read workspace glob {pattern}"))?
        {
            let path = entry.context("failed to read workspace glob entry")?;
            if path.is_dir() && path.join("package.json").is_file() {
                package_dirs.insert(path.canonicalize().unwrap_or(path));
            }
        }
    }

    let mut packages = Vec::new();
    for path in package_dirs {
        let package = read_package_json(&path)
            .with_context(|| format!("failed to read {}", path.join("package.json").display()))?;
        let relative_path = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        let package_kind = classify_package_kind(&relative_path);
        let env_status = env_status(&path);
        let setup_status = setup_status(&path, &env_status);
        let env_example_keys = env_example_keys(&path)?;
        let slug = app_slug(package.name.as_deref(), &relative_path);
        let project_name = format!("{workspace_name}:{slug}");
        let scripts = package.scripts.keys().cloned().collect::<Vec<_>>();
        let has_runtime_script = package.scripts.contains_key("dev")
            || package.scripts.contains_key("start")
            || package.scripts.contains_key("payload");
        let app_candidate = package_kind == WorkspacePackageKind::App
            || env_status != WorkspaceEnvStatus::Missing
            || has_runtime_script;

        packages.push(WorkspacePackage {
            name: package.name,
            slug,
            project_name,
            relative_path,
            path,
            package_kind,
            app_candidate,
            env_status,
            setup_status,
            env_example_keys,
            scripts,
        });
    }
    Ok(packages)
}

fn read_package_json(path: &Path) -> Result<PackageJson> {
    let package_path = path.join("package.json");
    let contents = fs::read_to_string(&package_path)
        .with_context(|| format!("failed to read {}", package_path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse {}", package_path.display()))
}

fn workspace_globs_from_package_json(package: &PackageJson) -> Vec<String> {
    match &package.workspaces {
        Some(WorkspacesField::List(packages)) => packages.clone(),
        Some(WorkspacesField::Object { packages }) => packages.clone(),
        None => Vec::new(),
    }
}

fn workspace_globs_from_pnpm(root: &Path) -> Result<Vec<String>> {
    let path = root.join("pnpm-workspace.yaml");
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(parse_pnpm_workspace_packages(&contents))
}

fn parse_pnpm_workspace_packages(contents: &str) -> Vec<String> {
    let mut in_packages = false;
    let mut patterns = Vec::new();
    for raw_line in contents.lines() {
        let line_without_comment = raw_line.split('#').next().unwrap_or("").trim_end();
        let trimmed = line_without_comment.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !raw_line.starts_with(' ') && !raw_line.starts_with('\t') {
            in_packages = trimmed == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        if let Some(pattern) = trimmed.strip_prefix('-') {
            let pattern = pattern.trim().trim_matches('"').trim_matches('\'');
            if !pattern.is_empty() {
                patterns.push(pattern.to_string());
            }
        }
    }
    patterns
}

fn classify_package_kind(relative_path: &Path) -> WorkspacePackageKind {
    match relative_path
        .components()
        .next()
        .and_then(|part| part.as_os_str().to_str())
    {
        Some("apps") => WorkspacePackageKind::App,
        _ => WorkspacePackageKind::Package,
    }
}

fn env_status(path: &Path) -> WorkspaceEnvStatus {
    if path.join(".env").is_file() {
        WorkspaceEnvStatus::Present
    } else if path.join(".env.example").is_file() {
        WorkspaceEnvStatus::ExampleOnly
    } else {
        WorkspaceEnvStatus::Missing
    }
}

fn setup_status(path: &Path, env_status: &WorkspaceEnvStatus) -> WorkspaceSetupStatus {
    if config::config_path(path).is_file() {
        WorkspaceSetupStatus::Configured
    } else if *env_status == WorkspaceEnvStatus::ExampleOnly {
        WorkspaceSetupStatus::NeedsEnv
    } else {
        WorkspaceSetupStatus::NotConfigured
    }
}

fn env_example_keys(path: &Path) -> Result<Vec<String>> {
    let example = path.join(".env.example");
    if !example.is_file() {
        return Ok(Vec::new());
    }
    let contents = fs::read_to_string(&example)
        .with_context(|| format!("failed to read {}", example.display()))?;
    Ok(parse_env_example_keys(&contents))
}

fn parse_env_example_keys(contents: &str) -> Vec<String> {
    let mut keys = BTreeSet::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        let Some((key, _)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if is_env_key_name(key) {
            keys.insert(key.to_string());
        }
    }
    keys.into_iter().collect()
}

fn is_env_key_name(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && key
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn workspace_name(root: &Path, package_name: Option<&str>) -> String {
    package_name
        .map(project_slug)
        .filter(|name| !name.is_empty())
        .or_else(|| {
            root.file_name()
                .and_then(|name| name.to_str())
                .map(project_slug)
        })
        .unwrap_or_else(|| "workspace".to_string())
}

fn app_slug(package_name: Option<&str>, relative_path: &Path) -> String {
    package_name
        .and_then(|name| name.rsplit('/').next())
        .map(project_slug)
        .filter(|slug| !slug.is_empty())
        .or_else(|| {
            relative_path
                .file_name()
                .and_then(|name| name.to_str())
                .map(project_slug)
        })
        .unwrap_or_else(|| "app".to_string())
}

fn project_slug(value: &str) -> String {
    let mut out = String::new();
    for ch in value.trim_start_matches('@').chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else if ch == '/' || ch == '.' || ch == ' ' {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

fn package_manager_name(value: &str) -> Option<String> {
    ["pnpm", "npm", "yarn", "bun"]
        .iter()
        .find(|candidate| value.starts_with(&format!("{candidate}@")))
        .map(|candidate| (*candidate).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_pnpm_turborepo_apps_and_skips_library_by_default() {
        let tempdir = tempfile::tempdir().unwrap();
        fs::write(
            tempdir.path().join("package.json"),
            r#"{"name":"cms-core","packageManager":"pnpm@9.15.9"}"#,
        )
        .unwrap();
        fs::write(
            tempdir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - \"apps/*\"\n  - \"packages/*\"\n",
        )
        .unwrap();
        fs::write(tempdir.path().join("turbo.json"), "{}").unwrap();

        for (dir, name, env_file, env_example) in [
            ("apps/ambienta", "@cms-app/ambienta", false, true),
            ("apps/core-workbench", "@cms-app/core-workbench", true, true),
            ("apps/creativestudio", "@cms-app/creativestudio", true, true),
            ("packages/cms-core", "@cms-core/platform", false, false),
        ] {
            let path = tempdir.path().join(dir);
            fs::create_dir_all(&path).unwrap();
            fs::write(
                path.join("package.json"),
                format!(r#"{{"name":"{name}","scripts":{{"dev":"next dev"}}}}"#),
            )
            .unwrap();
            if env_file {
                fs::write(path.join(".env"), "DATABASE_URI=mongodb://secret\n").unwrap();
            }
            if env_example {
                fs::write(
                    path.join(".env.example"),
                    "DATABASE_URI=\nPAYLOAD_SECRET=\n",
                )
                .unwrap();
            }
        }

        fs::write(
            tempdir.path().join("packages/cms-core/package.json"),
            r#"{"name":"@cms-core/platform","scripts":{"build":"tsc"}}"#,
        )
        .unwrap();

        let discovery = discover(tempdir.path()).unwrap().unwrap();
        assert!(discovery.turborepo);
        assert_eq!(discovery.package_manager.as_deref(), Some("pnpm"));
        let apps = discovery
            .app_candidates()
            .map(|package| package.slug.as_str())
            .collect::<Vec<_>>();
        assert_eq!(apps, vec!["ambienta", "core-workbench", "creativestudio"]);
        assert_eq!(discovery.packages[0].project_name, "cms-core:ambienta");
        assert_eq!(
            discovery.packages[0].env_status,
            WorkspaceEnvStatus::ExampleOnly
        );
        assert_eq!(
            discovery.packages[0].setup_status,
            WorkspaceSetupStatus::NeedsEnv
        );
        assert!(discovery.packages[0]
            .env_example_keys
            .contains(&"PAYLOAD_SECRET".to_string()));
    }

    #[test]
    fn package_json_workspaces_are_supported() {
        let tempdir = tempfile::tempdir().unwrap();
        fs::write(
            tempdir.path().join("package.json"),
            r#"{"name":"root","workspaces":["apps/*"]}"#,
        )
        .unwrap();
        let app = tempdir.path().join("apps/site");
        fs::create_dir_all(&app).unwrap();
        fs::write(
            app.join("package.json"),
            r#"{"name":"@scope/site","scripts":{"dev":"vite"}}"#,
        )
        .unwrap();

        let discovery = discover(tempdir.path()).unwrap().unwrap();
        assert_eq!(discovery.packages.len(), 1);
        assert_eq!(discovery.packages[0].project_name, "root:site");
    }

    #[test]
    fn env_example_key_parser_ignores_values_and_invalid_lines() {
        let keys = parse_env_example_keys(
            r#"
            # comment
            DATABASE_URI=<fill me>
            export PAYLOAD_SECRET=
            not a dotenv line
            1_BAD=value
            NEXT_PUBLIC_SERVER_URL=http://localhost:3000
            "#,
        );
        assert_eq!(
            keys,
            vec![
                "DATABASE_URI".to_string(),
                "NEXT_PUBLIC_SERVER_URL".to_string(),
                "PAYLOAD_SECRET".to_string(),
            ]
        );
    }
}
