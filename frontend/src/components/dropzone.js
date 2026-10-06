export function createDropzone({ onFiles, multiple = false }) {
  const wrapper = document.createElement("div");
  wrapper.className = "dropzone";
  wrapper.innerHTML = `
    <input type="file" ${multiple ? "multiple" : ""} />
    <div class="upload-icon" aria-hidden="true">↑</div>
    <strong>Drop ${multiple ? "files" : "a file"} here</strong>
    <span>or <button type="button" class="text-button">Browse files</button></span>
    <small>Files are protected before persistent storage.</small>
  `;

  const input = wrapper.querySelector("input");
  const browse = wrapper.querySelector(".text-button");

  const emit = (files) => {
    const list = Array.from(files || []);
    if (list.length) onFiles(multiple ? list : [list[0]]);
  };

  browse.addEventListener("click", () => input.click());
  wrapper.addEventListener("click", (event) => {
    if (event.target.closest(".text-button")) return;
    if (!event.target.closest("button")) input.click();
  });

  wrapper.addEventListener("dragover", (event) => {
    event.preventDefault();
    wrapper.classList.add("dragging");
  });

  wrapper.addEventListener("dragleave", () => {
    wrapper.classList.remove("dragging");
  });

  wrapper.addEventListener("drop", (event) => {
    event.preventDefault();
    wrapper.classList.remove("dragging");
    emit(event.dataTransfer.files);
  });

  input.addEventListener("change", () => emit(input.files));

  return wrapper;
}
