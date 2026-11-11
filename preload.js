const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("api", {
  info: () => ipcRenderer.invoke("info:get"),
  setConfig: (c) => ipcRenderer.invoke("cfg:set", c),
  openSetup: () => ipcRenderer.invoke("cfg:setup"),
  pickExcel: () => ipcRenderer.invoke("excel:pick"),
  savePdf: (o) => ipcRenderer.invoke("pdf:save", o),
  openWhatsApp: (o) => ipcRenderer.invoke("wa:open", o),
  openMail: (o) => ipcRenderer.invoke("mail:open", o),
  setBackground: (on) => ipcRenderer.invoke("bg:set", on),
  showFile: (p) => ipcRenderer.invoke("file:show", p)
});
