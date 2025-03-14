import { NavLink } from "react-router-dom";
import styles from "./Header.module.scss";
import useStore from "@/store";

export const Header = () => {
    const { BalanceRupee } = useStore();

    return (
        <>
            <div className={styles.header__spacer} />
            <header className={styles.header}>
                <NavLink to={'clicker'} className={styles.logo}>
                    <img src={'./logo.png'}></img>
                </NavLink>

                <div className={styles.rightContainer}>
                    <div className={styles.balance}>
                        <span className={styles.title}>Balance</span>
                        <span>
                            <span className={styles.coin}>₹</span>
                            <span className={styles.count}>{Math.trunc(BalanceRupee) || '0'}</span>
                        </span>
                    </div>
                    <NavLink to={'/other'} className={styles.deposit}>
                        <span>Deposit</span>
                    </NavLink>
                </div>
              
            </header>
        </>
    );
};
