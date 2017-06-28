import React from 'react';
import {Link} from 'react-router'

class Root extends React.Component {

    render() {
        return ( 
            <div>
                <header className="navbar navbar-default">
                    <div className="container">
                        <div className="navbar-header">
                            <button type="button" className="navbar-toggle collapsed" data-toggle="collapse" data-target="#bs-example-navbar-collapse-1" aria-expanded="false">
                                <span className="sr-only">Toggle navigation</span>
                                <span className="icon-bar"></span>
                                <span className="icon-bar"></span>
                                <span className="icon-bar"></span>
                            </button>
                            <a className="navbar-brand" href="#"><img src="images/logo.png" alt=""/></a>
                        </div>

                        <div className="collapse navbar-collapse" id="bs-example-navbar-collapse-1">

                            <ul className="nav navbar-nav navbar-right">
                                <li><Link to={"/servers"} activeClassName={"activeNav"}>Servers</Link></li>
                                <li><Link to={"/users"} activeClassName={"activeNav"}>Users</Link></li>
                                <li><Link to={"/groups"} activeClassName={"activeNav"}>Groups</Link></li>
                            </ul>
                        </div>
                    </div>
                </header>
                    { this.props.children }
            </div>
        )
    }
}

export default Root;