import serversData from '../data/serversData';
import $ from 'jquery';

var serverList = $.parseJSON(JSON.stringify(serversData));


// const servers = serverList.map((map)=> {
//     const serverHeaderData = (
//         <div className="rowContainer serversRowContainer">
//             <li>{map.Internal_IP}</li>
//             <li>{map.Short_name}</li>
//             <li>{map.Operator}</li>
//             <li>Group name</li>
//         </div>
//     );
//
//     const serverData = (
//         <div className="serverData">
//             <ul>
//                 <li><b>Name: </b>{map.Short_name}</li>
//                 <li><b>Host Name:</b> {map.Host_name}</li>
//                 <li><b>IP: </b>{map.Internal_IP}</li>
//                 <li><b>Owner: </b>{map.Owner}</li>
//                 <li><b>App Version:</b> {map.App_Version}</li>
//                 <li><b>Environment: </b>{map.Environment}</li>
//                 <li><b>Managed By Cheaf?: </b> {map.Managed_By_chef}</li>
//                 <li><b>OS: </b>{map.OS_version}</li>
//             </ul>
//         </div>
//     );
//     return (
//         <Collapsible trigger={serverHeaderData} key={map.Internal_IP}>
//             {serverData}
//         </Collapsible>
//     );
// });

export default serverList;