// just a very dirty PoC

function waitForElement(selector, callback) {
  const intervalId = setInterval(() => {
    if (document.querySelector(selector)) {
      clearInterval(intervalId);
      callback();
    }
  }, 500);
}

const xhr = new XMLHttpRequest();
xhr.open("GET", "/pveportal/api/clusters");
xhr.send();
xhr.responseType = "json";
xhr.onload = () => waitForElement("#treeview-1013", createPvePortalClusters);

function createPvePortalClusters() {
  let clusters = document.createElement("div");
  clusters.setAttribute("id", "pveportal-clusters");
  clusters.style.position = "absolute";
  clusters.style.zIndex = 10;
  clusters.style.top = "0px";
  clusters.style.left = "0px";
  for (var i = 0; i < xhr.response.clusters.length; i++) {
    clusters.innerHTML += `<a
    href="${xhr.response.clusters[i].switch_url}"
    style="text-decoration:none;">
    <table
      role="presentation"
      class="x-grid-item"
      cellpadding="0"
      cellspacing="0"
      style="padding-left: 16px"
    >
    <div
    role="presentation"
    style="transform: translate3d(0px, 0px, 0px)"
    >
      <tbody>
        <tr
          class="x-grid-row"
          role="row"
          aria-level="1"
          aria-expanded="true"
        >
          <td
            class="x-grid-td"
            role="gridcell"
            tabindex="-1"
          >
            <div
              class="x-grid-cell-inner x-grid-cell-inner-treecolumn"
              style="text-align: left"
            >
              <div
                role="presentation"
                class="x-tree-icon x-tree-icon-custom x-tree-icon-parent-expanded fa fa-server"
              ></div>
              <span class="x-tree-node-text">Cluster ${xhr.response.clusters[i].name}</span>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    </div></a>`;
  }
  document.body.appendChild(clusters);
  document.getElementById("pveStatusPanel-1040").style.zIndex = 11;
  document.getElementById("pveStatusPanel-1040-splitter").style.zIndex = 11;
  document.getElementById("container-1037-splitter").style.zIndex = 11;
  document.getElementById("content").style.zIndex = 11;
  updatePvePortalClustersLoc();
  let obs = new MutationObserver(updatePvePortalClustersLoc);
  obs.observe(
    document
      .getElementById("treeview-1013")
      .getElementsByClassName("x-grid-item-container")[0],
    { attributes: true, childList: true, subtree: true }
  );
}

function updatePvePortalClustersLoc() {
  let rect = document
    .getElementById("treeview-1013")
    .getElementsByClassName("x-grid-item-container")[0]
    .getBoundingClientRect();
  document.getElementById("pveportal-clusters").style.top = rect.bottom + "px";
  document.getElementById("pveportal-clusters").style.left = rect.left + "px";
}
