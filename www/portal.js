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
xhr.onload = () => {
  waitForElement("#treeview-1013", () => {
    for (var i = 0; i < xhr.response.clusters.length; i++) {
      document.getElementById("treeview-1013").innerHTML += `<a
      href="${xhr.response.clusters[i].switch_url}"
      style="text-decoration:none;">
      <div
      class="x-grid-item-container"
      role="presentation"
      style="width: 298px; transform: translate3d(0px, 0px, 0px)"
      >
      <table
        role="presentation"
        class="x-grid-item"
        cellpadding="0"
        cellspacing="0"
        style="width: 0;padding-left: 16px"
      >
        <tbody>
          <tr
            class="x-grid-tree-node-expanded x-grid-row"
            role="row"
            data-qtip=""
            data-qtitle=""
            aria-level="1"
            aria-expanded="true"
          >
            <td
              class="x-grid-cell x-grid-td x-grid-cell-treecolumn x-grid-cell-first x-grid-cell-last x-unselectable"
              style="width: 298px"
              role="gridcell"
              tabindex="-1"
            >
              <div
                unselectable="on"
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
  });
};
