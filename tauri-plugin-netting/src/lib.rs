use tauri::{
  plugin::{Builder, TauriPlugin},
  Manager, Runtime,
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::Netting;
#[cfg(mobile)]
use mobile::Netting;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the netting APIs.
pub trait NettingExt<R: Runtime> {
  fn netting(&self) -> &Netting<R>;
}

impl<R: Runtime, T: Manager<R>> crate::NettingExt<R> for T {
  fn netting(&self) -> &Netting<R> {
    self.state::<Netting<R>>().inner()
  }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
  Builder::new("netting")
    .invoke_handler(tauri::generate_handler![commands::ping])
    .setup(|app, api| {
      #[cfg(mobile)]
      let netting = mobile::init(app, api)?;
      #[cfg(desktop)]
      let netting = desktop::init(app, api)?;
      app.manage(netting);
      Ok(())
    })
    .build()
}
