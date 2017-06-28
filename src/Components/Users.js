import React from 'react';
import Collapsible from 'react-collapsible';
import usersData from '../data/usersData';

class Users extends React.Component {

    constructor() {
        super();
        this.state = {
            search: ''
        }
    }

    onChange(e) {
        this.setState({
            search: e.target.value,
    })
        ;
    }

    render() {
        var userList = usersData.filter(
            (user) => {
                if(user.full_name.toLowerCase().indexOf(this.state.search.toLowerCase()) !== -1 || user.group.toLowerCase().indexOf(this.state.search.toLowerCase()) !== -1 ) {
                    return user;
                } else {
                    return false;
                }
            }
        );
        userList = userList.map((map)=> {
            const userHeaderData = (
                <div className="rowContainer serversRowContainer">
                    <li className="col-md-3 col-xs-3">{map.full_name}</li>
                    <li className="col-md-3 col-xs-3">{map.position}</li>
                    <li className="col-md-3 col-xs-3 userEmail">{map.email}</li>
                    <li className="col-md-3 col-xs-3">{map.group_name}</li>
                </div>
            );

            const userData = (
                <div className="serverData">
                    <ul>
                        <li className="col-md-3">{map.full_name}</li>
                        <li className="col-md-3">{map.position}</li>
                        <li className="col-md-3">{map.email}</li>
                        <li className="col-md-3">{map.group}</li>
                    </ul>
                </div>
            );
            return (
                <Collapsible trigger={userHeaderData} key={map.id}>
                    {userData}
                </Collapsible>
            );
        });
        return (
            <div className="container">
                <h2>Search:</h2>
                <div className="searchBox">
                    <input
                        type="text"
                        className="form-control"
                        onChange={ this.onChange.bind(this) }
                        value={this.state.search}
                    />
                </div>
                <div className="content serverContainer">
                    <div className="rowContainer clearfix">
                        <div className="rowHeader col-md-3 col-xs-3">Name</div>
                        <div className="rowHeader col-md-3 col-xs-3">Position</div>
                        <div className="rowHeader col-md-3 col-xs-3">Email</div>
                        <div className="rowHeader col-md-3 col-xs-3">Group</div>
                    </div>
                    {userList}
                </div>
            </div>
        )
    }
}

export default Users;